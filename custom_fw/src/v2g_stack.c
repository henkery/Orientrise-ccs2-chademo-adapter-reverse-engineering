/* v2g_stack.c — live V2G transport over vendored lwIP 2.1.x + mbedTLS 2.28 (see v2g_stack.h).
 * The recovered C013 transport glue wired to the REAL upstream libraries: lwIP raw API owns
 * IPv6/ND6/TCP/UDP (NO_SYS=1), mbedTLS owns the TLS 1.2 client (recovered config in
 * mbedtls_config.h / lwipopts.h). Communication only — NO power-stage GPIO.
 *
 * Data flow:
 *   RX  QCA7005 frame -> v2g_stack_rx_ethernet -> pbuf -> ethernet_input -> ip6_input ->
 *       tcp_input -> tcp_recv_cb -> [TLS] rx ring -> mbedTLS bio_recv -> ssl_read -> app_recv;
 *       [plain] app_recv directly. UDP -> udp_recv_cb -> SDP.
 *   TX  app -> [TLS] ssl_write -> bio_send -> tcp_write/tcp_output; [plain] tcp_write/output ->
 *       ip6_output_if -> ethip6_output -> netif linkoutput -> eth_send (qca7005_frame_send).
 *   ND6 lwIP nd6_input/nd6_tmr resolve the SECC link-local -> MAC (the recovered nd6 symbols). */
#include "v2g_stack.h"
#include "libc_shim.h"

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/ethip6.h"
#include "lwip/timeouts.h"
#include "lwip/pbuf.h"
#include "lwip/nd6.h"
#include "netif/ethernet.h"

#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/memory_buffer_alloc.h"

/* ---- module state ---- */
static struct netif qca_netif;
static struct udp_pcb *sdp_pcb;
static struct tcp_pcb *v2g_pcb;
static uint8_t stack_mac[6];
static v2g_stack_eth_send_fn eth_send_fn;
static v2g_stack_connected_fn cb_connected;
static v2g_stack_app_recv_fn cb_app_recv;
static v2g_stack_closed_fn cb_closed;
static v2g_stack_udp_recv_fn cb_udp_recv;
static v2g_stack_rng_fn rng_fn;
static void *rng_ctx;
static uint8_t stack_up;

/* TLS bio recv ring: lwIP tcp_recv_cb pushes; mbedTLS bio_recv pulls (WANT_READ when empty). */
static uint8_t rx_ring[V2G_STACK_RX_RING_SIZE];
static uint16_t rx_head, rx_tail;   /* head=write, tail=read; full when (head+1)%SIZE==tail */

/* mbedTLS static heap (MBEDTLS_MEMORY_BUFFER_ALLOC_C) in CCM RAM — no libc malloc. Sized for one
 * TLS session: 2x8509 record buffers + ECDHE/X509/ECP handshake transient (recovered 0x20020314). */
static unsigned char mbedtls_heap[65536] __attribute__((section(".ccm_bss")));

/* mbedTLS context (recovered ssl ctx 0x20020314 + 2x8509 record buffers, allocated from heap). */
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt ca_chain;
static uint8_t tls_active;
static const int tls_ciphers[] = {
    0xC023,   /* TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256 (recovered cipher list 0x080B0668) */
    0xC025,   /* TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256 */
    0
};

/* ---- rx ring helpers ---- */
static uint16_t ring_push(const uint8_t *data, uint16_t len)
{
    uint16_t pushed = 0;
    for (uint16_t i = 0; i < len; i++) {
        uint16_t nh = (uint16_t)((rx_head + 1u) % V2G_STACK_RX_RING_SIZE);
        if (nh == rx_tail) break;            /* full: drop (TCP window stalls upstream) */
        rx_ring[rx_head] = data[i];
        rx_head = nh;
        pushed++;
    }
    return pushed;
}
static uint16_t ring_pull(uint8_t *out, uint16_t cap)
{
    uint16_t n = 0;
    while (n < cap && rx_tail != rx_head) {
        out[n++] = rx_ring[rx_tail];
        rx_tail = (uint16_t)((rx_tail + 1u) % V2G_STACK_RX_RING_SIZE);
    }
    return n;
}

/* ---- netif (QCA7005 Ethernet) ---- */
static err_t linkoutput_cb(struct netif *nif, struct pbuf *p)
{
    (void)nif;
    uint8_t tx[1518];
    uint16_t len = p->tot_len > sizeof tx ? (uint16_t)sizeof tx : p->tot_len;
    pbuf_copy_partial(p, tx, len, 0);
    if (eth_send_fn) eth_send_fn(tx, len);
    return ERR_OK;
}

static err_t netif_init_cb(struct netif *nif)
{
    nif->name[0] = 'q'; nif->name[1] = 'c';
    nif->hwaddr_len = 6;
    memcpy(nif->hwaddr, stack_mac, 6);
    nif->mtu = 1500;
    nif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHERNET | NETIF_FLAG_LINK_UP;
    nif->output_ip6 = ethip6_output;    /* IPv6 output (recovered ethip6_output 0x0809B35C) */
    nif->linkoutput = linkoutput_cb;    /* -> QCA7005 SPI buf-WRITE */
    return ERR_OK;
}

/* ---- UDP SDP ---- */
static void udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                        const ip_addr_t *addr, u16_t port)
{
    (void)arg; (void)pcb; (void)addr; (void)port;
    if (p && cb_udp_recv) {
        uint8_t buf[128];
        uint16_t n = p->tot_len > sizeof buf ? (uint16_t)sizeof buf : p->tot_len;
        pbuf_copy_partial(p, buf, n, 0);
        cb_udp_recv(buf, n);
    }
    if (p) pbuf_free(p);
}

/* ---- TCP raw-API callbacks ---- */
static void deliver_app(const uint8_t *data, uint16_t len)
{
    if (cb_app_recv) cb_app_recv(data, len);
}

/* In TLS mode, decrypt any complete records now available and deliver application data. */
static void tls_drain_read(void)
{
    if (!tls_active || ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) return;
    uint8_t buf[1024];
    for (;;) {
        int r = mbedtls_ssl_read(&ssl, buf, sizeof buf);
        if (r > 0) { deliver_app(buf, (uint16_t)r); continue; }
        break;   /* 0 / WANT_READ / error: stop (poll retries) */
    }
}

static err_t tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    (void)arg; (void)err;
    if (p == NULL) {                      /* remote closed */
        tcp_close(pcb);
        if (v2g_pcb == pcb) v2g_pcb = NULL;
        if (cb_closed) cb_closed();
        return ERR_OK;
    }
    uint8_t tmp[1518];
    uint16_t n = p->tot_len > sizeof tmp ? (uint16_t)sizeof tmp : p->tot_len;
    pbuf_copy_partial(p, tmp, n, 0);
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    if (tls_active) {
        ring_push(tmp, n);                /* mbedTLS bio_recv pulls from the ring */
        tls_drain_read();
    } else {
        deliver_app(tmp, n);              /* plain: V2GTP deframe upstream */
    }
    return ERR_OK;
}

static void tcp_err_cb(void *arg, err_t err)
{
    (void)arg; (void)err;
    v2g_pcb = NULL;                       /* lwIP frees the pcb after err */
    if (cb_closed) cb_closed();
}

static err_t tcp_poll_cb(void *arg, struct tcp_pcb *pcb)
{
    (void)arg; (void)pcb;
    if (tls_active) tls_drain_read();
    return ERR_OK;
}

static err_t tcp_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)arg; (void)pcb;
    if (err == ERR_OK) { if (cb_connected) cb_connected(); }
    else { if (cb_closed) cb_closed(); }
    return ERR_OK;
}

/* ---- mbedTLS bio (bridge to the lwIP tcp pcb + rx ring) ---- */
static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    (void)ctx;
    if (!v2g_pcb) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    err_t e = tcp_write(v2g_pcb, buf, (u16_t)len, TCP_WRITE_FLAG_COPY);
    if (e == ERR_MEM) return MBEDTLS_ERR_SSL_WANT_WRITE;
    if (e != ERR_OK) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    tcp_output(v2g_pcb);
    return (int)len;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    uint16_t n = ring_pull(buf, (uint16_t)len);
    if (n == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    return (int)n;
}

/* ---- public API ---- */

void v2g_stack_init(const uint8_t mac[6], v2g_stack_eth_send_fn eth_send)
{
    memcpy(stack_mac, mac, 6);
    eth_send_fn = eth_send;
    rx_head = rx_tail = 0;
    tls_active = 0;
    if (!stack_up) {
        lwip_init();
        mbedtls_memory_buffer_alloc_init(mbedtls_heap, sizeof mbedtls_heap);
        stack_up = 1;
    }
    netif_add(&qca_netif, NULL, netif_init_cb, ethernet_input);   /* IPv4-off: 4-arg form */
    netif_set_default(&qca_netif);
    netif_set_link_up(&qca_netif);
    netif_create_ip6_linklocal_address(&qca_netif, 1);   /* fe80::/64 + EUI-64 (0x08090D68) */
    sdp_pcb = udp_new();
    if (sdp_pcb) {
        udp_bind(sdp_pcb, IP_ADDR_ANY, V2G_STACK_UDP_SRC_PORT);
        udp_recv(sdp_pcb, udp_recv_cb, NULL);
    }
}

void v2g_stack_set_rng(v2g_stack_rng_fn fn, void *ctx) { rng_fn = fn; rng_ctx = ctx; }

void v2g_stack_local_ip(uint8_t out[16])
{
    const ip6_addr_t *ll = netif_ip6_addr(&qca_netif, 0);
    memcpy(out, ll->addr, 16);
}

void v2g_stack_rx_ethernet(const uint8_t *frame, uint16_t len)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (!p) return;
    pbuf_take(p, frame, len);
    if (qca_netif.input(p, &qca_netif) != ERR_OK) pbuf_free(p);
}

void v2g_stack_poll(uint32_t now_ms)
{
    extern volatile uint32_t lwip_now_ms;   /* libc_shim sys_now source */
    lwip_now_ms = now_ms;
    sys_check_timeouts();                   /* tcp_tmr / nd6_tmr / ip6_reass_tmr */
    if (tls_active) tls_drain_read();
}

void v2g_stack_set_udp_recv(v2g_stack_udp_recv_fn fn) { cb_udp_recv = fn; }

int v2g_stack_udp_send(const uint8_t *data, uint16_t len)
{
    if (!sdp_pcb || len == 0) return -1;
    ip_addr_t mcast;
    IP_SET_TYPE(&mcast, IPADDR_TYPE_V6);
    ip6addr_aton("ff02::1", ip_2_ip6(&mcast));
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) return -1;
    pbuf_take(p, data, len);
    err_t e = udp_sendto(sdp_pcb, p, &mcast, V2G_STACK_SDP_PORT);
    pbuf_free(p);
    return e == ERR_OK ? (int)len : -1;
}

void v2g_stack_set_tcp_cbs(v2g_stack_connected_fn connected, v2g_stack_app_recv_fn recv,
                           v2g_stack_closed_fn closed)
{
    cb_connected = connected; cb_app_recv = recv; cb_closed = closed;
}

int v2g_stack_tcp_connect(const uint8_t secc_ip[16], uint16_t port)
{
    if (v2g_pcb) { tcp_close(v2g_pcb); v2g_pcb = NULL; }
    rx_head = rx_tail = 0;
    v2g_pcb = tcp_new();
    if (!v2g_pcb) return -1;
    tcp_arg(v2g_pcb, NULL);
    tcp_recv(v2g_pcb, tcp_recv_cb);
    tcp_err(v2g_pcb, tcp_err_cb);
    tcp_poll(v2g_pcb, tcp_poll_cb, 2);
    ip_addr_t dst;
    IP_SET_TYPE(&dst, IPADDR_TYPE_V6);
    memcpy(ip_2_ip6(&dst)->addr, secc_ip, 16);
    err_t e = tcp_connect(v2g_pcb, &dst, port, tcp_connected_cb);
    if (e != ERR_OK) { tcp_close(v2g_pcb); v2g_pcb = NULL; return -1; }
    return 0;
}

int v2g_stack_tcp_send(const uint8_t *data, uint16_t len)
{
    if (!v2g_pcb) return -1;
    err_t e = tcp_write(v2g_pcb, data, len, TCP_WRITE_FLAG_COPY);
    if (e != ERR_OK) return -1;
    tcp_output(v2g_pcb);
    return (int)len;
}

void v2g_stack_tcp_close(void)
{
    if (v2g_pcb) { tcp_close(v2g_pcb); v2g_pcb = NULL; }
}

int v2g_stack_tcp_is_connected(void)
{
    return v2g_pcb && (v2g_pcb->state == ESTABLISHED);
}

int v2g_stack_tls_setup(const ca_store_t *ca)
{
    if (!rng_fn) return -1;
    int r;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&ca_chain);
    r = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (r != 0) return r;
    mbedtls_ssl_conf_ciphersuites(&conf, tls_ciphers);          /* {0xC023,0xC025,0} */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);  /* recovered authmode 2 */
    mbedtls_ssl_conf_rng(&conf, rng_fn, rng_ctx);
    /* Load the ca_store Root certs (DER) into the trust chain (recovered 0x080208CA loop). */
    if (ca) {
        for (uint8_t i = 0; i < ca->root_count && i < CA_ROOT_SLOTS; i++) {
            const ca_entry_t *e = &ca->root[i];
            if (e->der_len == 0 || e->der_len > CA_DER_MAX) continue;
            r = mbedtls_x509_crt_parse(&ca_chain, e->der, e->der_len);   /* DER: exact byte length */
            if (r < 0) return r;
        }
    }
    mbedtls_ssl_conf_ca_chain(&conf, &ca_chain, NULL);
    mbedtls_ssl_set_bio(&ssl, NULL, bio_send, bio_recv, NULL);
    r = mbedtls_ssl_setup(&ssl, &conf);
    if (r != 0) return r;
    tls_active = 1;
    return 0;
}

int v2g_stack_tls_handshake(void)
{
    int r = mbedtls_ssl_handshake(&ssl);
    if (r == 0) return 0;
    if (r == MBEDTLS_ERR_SSL_WANT_READ) return 1;
    if (r == MBEDTLS_ERR_SSL_WANT_WRITE) return 2;
    return r;   /* fatal */
}

int v2g_stack_tls_write(const uint8_t *data, uint16_t len)
{
    return mbedtls_ssl_write(&ssl, data, len);   /* bytes written or negative error */
}

int v2g_stack_tls_read(uint8_t *out, uint16_t cap)
{
    int r = mbedtls_ssl_read(&ssl, out, cap);
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    return r;
}

int v2g_stack_tls_done(void) { return ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER; }

void v2g_stack_tls_free(void)
{
    if (tls_active) {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_x509_crt_free(&ca_chain);
        tls_active = 0;
    }
}
