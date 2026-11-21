/* v2g_net.c — V2G network transport SM + V2GTP deframe + EXI dispatch (REPORT §5.9, Agent G/H).
 * See v2g_net.h. The LIVE IPv6/ND6/TCP/UDP stack + TLS 1.2 crypto are now the REAL vendored
 * libraries (lwIP 2.1.x + mbedTLS 2.28, configured byte-exact in lwipopts.h / mbedtls_config.h)
 * via v2g_stack.c — the stock C013 firmware IS lwIP + mbedTLS. This module keeps the recovered
 * adapter GLUE: the transport connection SM (connect/handshake/established/idle-close), the TLS
 * decision (TLS iff SECC security byte==0), the V2GTP stream deframe, EXI dispatch -> ccs2_rx_exi,
 * and the diagnostic trace ring. The pure wire helpers below are byte-exact reference framing
 * (host-tested documentation of what lwIP emits); the live path uses lwIP framing.
 * Communication only — NO power-stage GPIO. */
#include "v2g_net.h"
#include "v2gtp.h"
#include "sdp.h"
#include "ccs2.h"
#include "v2g_stack.h"
#include "ca_store.h"

static v2g_net_t net;
static v2g_net_eth_send_fn eth_send;
static v2g_deframe_t df;
static uint8_t trace_ring[16][128];   /* diagnostic TRACE buffer (0x20001FEC) */
static uint8_t local_mac[6];          /* adapter Ethernet src MAC (QCA7005 PIB MAC; netif hwaddr) */
static uint32_t net_now;              /* current ms timestamp for the stack callbacks */
static void deframe_cb(const uint8_t *frame, uint16_t len, void *arg);

static void z(uint8_t *p, uint16_t n) { for (uint16_t i = 0; i < n; i++) p[i] = 0; }
static void cp(uint8_t *d, const uint8_t *s, uint16_t n) { for (uint16_t i = 0; i < n; i++) d[i] = s[i]; }
static void put16be(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32be(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
                                            p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static uint16_t get16be(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }

/* ---- pure wire helpers (byte-exact reference framing; live path uses lwIP) ---- */

void v2g_net_ipv6_linklocal(const uint8_t mac[6], uint8_t out[16])
{
    /* 0x08090D68: fe80::/64 + modified-EUI-64 IID [hw0^2,hw1,hw2,FF,FE,hw3,hw4,hw5]. */
    z(out, 16);
    out[0] = 0xFE; out[1] = 0x80;
    out[8]  = (uint8_t)(mac[0] ^ 0x02u);
    out[9]  = mac[1];
    out[10] = mac[2];
    out[11] = 0xFF;
    out[12] = 0xFE;
    out[13] = mac[3];
    out[14] = mac[4];
    out[15] = mac[5];
}

void v2g_net_ipv6_mcast_mac(const uint8_t dst[16], uint8_t out[6])
{
    /* 0x0809B35C ethip6_output: multicast MAC = 33:33:dst[12..15]. */
    out[0] = 0x33; out[1] = 0x33;
    out[2] = dst[12]; out[3] = dst[13]; out[4] = dst[14]; out[5] = dst[15];
}

uint16_t v2g_net_ip6_build(uint8_t *out, uint16_t payload_len, uint8_t next_hdr,
                           uint8_t hop_limit, const uint8_t src[16], const uint8_t dst[16])
{
    put32be(out, 0x60000000u);
    put16be(out + 4, payload_len);
    out[6] = next_hdr;
    out[7] = hop_limit;
    cp(out + 8, src, 16);
    cp(out + 24, dst, 16);
    return V2G_IP6_HDR_LEN;
}

int v2g_net_ip6_parse(const uint8_t *hdr, uint16_t len, uint16_t *payload_len, uint8_t *next_hdr)
{
    if (len < V2G_IP6_HDR_LEN) return 0;
    if ((hdr[0] >> 4) != V2G_IP6_VERSION) return 0;
    if (payload_len) *payload_len = get16be(hdr + 4);
    if (next_hdr) *next_hdr = hdr[6];
    return 1;
}

uint16_t v2g_net_udp_build(uint8_t *out, uint16_t src_port, uint16_t dst_port, uint16_t payload_len)
{
    put16be(out, src_port);
    put16be(out + 2, dst_port);
    put16be(out + 4, (uint16_t)(payload_len + V2G_UDP_HDR_LEN));
    put16be(out + 6, 0);
    return V2G_UDP_HDR_LEN;
}

uint16_t v2g_net_tcp_build(uint8_t *out, uint16_t src_port, uint16_t dst_port, uint32_t seq,
                           uint32_t ack, uint8_t flags, uint16_t window)
{
    put16be(out, src_port);
    put16be(out + 2, dst_port);
    put32be(out + 4, seq);
    put32be(out + 8, ack);
    out[12] = (uint8_t)((V2G_TCP_HDR_LEN / 4u) << 4);
    out[13] = flags;
    put16be(out + 14, window);
    put16be(out + 16, 0);
    put16be(out + 18, 0);
    return V2G_TCP_HDR_LEN;
}

uint16_t v2g_net_inet_chksum(const uint8_t *buf, uint16_t len)
{
    uint32_t sum = 0;
    uint16_t i = 0;
    for (; (uint16_t)(i + 1) < len; i += 2)
        sum += (uint32_t)(((uint16_t)buf[i] << 8) | buf[i + 1]);
    if (i < len) sum += (uint32_t)((uint16_t)buf[i] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

uint16_t v2g_net_ip6_pseudo_chksum(const uint8_t src[16], const uint8_t dst[16],
                                   uint8_t next_hdr, const uint8_t *payload, uint16_t payload_len)
{
    uint8_t ph[40];
    cp(ph, src, 16);
    cp(ph + 16, dst, 16);
    put32be(ph + 32, payload_len);
    ph[36] = 0; ph[37] = 0; ph[38] = 0; ph[39] = next_hdr;
    uint32_t sum = 0;
    for (uint16_t i = 0; i < 40; i += 2)
        sum += (uint32_t)(((uint16_t)ph[i] << 8) | ph[i + 1]);
    uint16_t j = 0;
    for (; (uint16_t)(j + 1) < payload_len; j += 2)
        sum += (uint32_t)(((uint16_t)payload[j] << 8) | payload[j + 1]);
    if (j < payload_len) sum += (uint32_t)((uint16_t)payload[j] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    uint16_t c = (uint16_t)(~sum & 0xFFFFu);
    return c ? c : 0xFFFFu;
}

uint16_t v2g_net_eth_build(uint8_t *out, const uint8_t dst[6], const uint8_t src[6], uint16_t ethertype)
{
    cp(out, dst, 6);
    cp(out + 6, src, 6);
    put16be(out + 12, ethertype);
    return V2G_ETH_HDR_LEN;
}

uint16_t v2g_net_ethertype(const uint8_t *frame, uint16_t len)
{
    if (len < V2G_ETH_HDR_LEN) return 0;
    return get16be(frame + 12);
}

/* ---- live-stack callbacks (lwIP raw API + mbedTLS, via v2g_stack) ---- */

/* TCP connected event (lwIP connected-cb -> stock connected-cb 0x08060ACE). */
static void stack_connected_cb(void) { v2g_net_tcp_connected(net_now); }

/* Application bytes from the stack: plain = raw V2GTP; TLS = mbedTLS-decrypted V2GTP. Both are
 * deframed identically (the TLS record layer is now inside mbedTLS, not reassembled here). */
static void stack_app_recv_cb(const uint8_t *data, uint16_t len)
{
    net.last_rx = net_now; net.idle_polls = 0;
    v2g_deframe_push(&df, data, len, deframe_cb, &net_now);
}

/* TCP error/close (lwIP err-cb / remote FIN -> stock err cb 0x08060A44). */
static void stack_closed_cb(void) { v2g_net_tcp_closed(); }

/* UDP SDP response (lwIP udp recv-cb -> stock recv_cb 0x08060966 -> SDP SM). */
static void stack_udp_recv_cb(const uint8_t *data, uint16_t len)
{
    net.last_rx = net_now; net.idle_polls = 0;
    sdp_rx(data, len);
}

/* ---- V2GTP stream deframe ---- */

void v2g_deframe_init(v2g_deframe_t *df) { df->len = 0; }

uint16_t v2g_deframe_push(v2g_deframe_t *df, const uint8_t *data, uint16_t len,
                          v2g_deframe_cb cb, void *arg)
{
    uint16_t frames = 0;
    for (uint16_t i = 0; i < len; i++) {
        if (df->len < V2G_DEFRAME_BUF_SIZE) df->buf[df->len++] = data[i];
        else { df->len = 0; }
        while (df->len >= V2GTP_HDR_LEN) {
            if (df->buf[0] != V2GTP_VER || df->buf[1] != V2GTP_INV) {
                for (uint16_t k = 1; k < df->len; k++) df->buf[k - 1] = df->buf[k];
                df->len--;
                continue;
            }
            uint32_t l = ((uint32_t)df->buf[4] << 24) | ((uint32_t)df->buf[5] << 16) |
                         ((uint32_t)df->buf[6] << 8) | (uint32_t)df->buf[7];
            uint32_t framelen32 = l + V2GTP_HDR_LEN;
            if (framelen32 > V2G_DEFRAME_BUF_SIZE) {
                for (uint16_t k = 1; k < df->len; k++) df->buf[k - 1] = df->buf[k];
                df->len--;
                continue;
            }
            uint16_t framelen = (uint16_t)framelen32;
            if (df->len < framelen) break;
            if (cb) cb(df->buf, framelen, arg);
            frames++;
            uint16_t rem = (uint16_t)(df->len - framelen);
            for (uint16_t k = 0; k < rem; k++) df->buf[k] = df->buf[framelen + k];
            df->len = rem;
        }
    }
    return frames;
}

/* ---- TLS decision (CORRECTED; state4 0x080207BC) ---- */

uint8_t v2g_net_tls_decision(uint8_t secc_security)
{
    /* TLS iff SECC security byte == 0 (wire 0x00=TLS / 0x10=No-TLS). */
    return (secc_security == 0u) ? 1u : 0u;
}

/* ---- transport SM ---- */

void v2g_net_init(void)
{
    z((uint8_t *)&net, sizeof net);
    net.state = V2G_NET_IDLE;
    net.mode = V2G_NET_MODE_NONE;
    net.ciphers[0] = V2G_TLS_CIPHER_ECDHE_ECDSA_AES128_CBC_SHA256;   /* 0xC023 */
    net.ciphers[1] = V2G_TLS_CIPHER_ECDH_ECDSA_AES128_CBC_SHA256;    /* 0xC025 */
    net.authmode = V2G_TLS_AUTHMODE_VERIFY_REQUIRED;                 /* 2 */
    v2g_deframe_init(&df);
    local_mac[0] = 0xFE; local_mac[1] = 0xFF; local_mac[2] = 0xFE;
    local_mac[3] = 0xFF; local_mac[4] = 0x00; local_mac[5] = 0x01;
}

void v2g_net_set_eth_send(v2g_net_eth_send_fn fn) { eth_send = fn; }
void v2g_net_set_tls_wrap(v2g_net_tls_wrap_fn fn) { (void)fn; }   /* legacy hook: TLS is now real */

void v2g_net_set_local_mac(const uint8_t mac[6])
{
    /* ethernetif_init 0x08093202 (from_mac=1) + netif_create_ip6_linklocal_address 0x08090D68:
     * bring up the lwIP netif with the PIB MAC, derive the EUI-64 link-local, wire the callbacks. */
    cp(local_mac, mac, 6);
    v2g_stack_init(mac, eth_send);
    v2g_stack_local_ip(net.local_ip);
    v2g_stack_set_tcp_cbs(stack_connected_cb, stack_app_recv_cb, stack_closed_cb);
    v2g_stack_set_udp_recv(stack_udp_recv_cb);
}
const v2g_net_t *v2g_net_get(void) { return &net; }

void v2g_net_start_tcp(const uint8_t secc_ip[16], uint16_t secc_port, uint8_t secc_security,
                       uint32_t now_ms)
{
    /* state3 0x0802070E: UDP close + TCP connect, arm timer 30000; TLS decision (state4) up front. */
    cp(net.secc_ip, secc_ip, 16);
    net.secc_port = secc_port;
    net.use_tls = v2g_net_tls_decision(secc_security);
    net.mode = net.use_tls ? V2G_NET_MODE_TLS : V2G_NET_MODE_PLAIN;
    net.tcp_connected = 0;
    net.tls_done = net.use_tls ? 0u : 1u;
    net.ts_connect = now_ms;
    net.last_rx = now_ms;
    net.idle_polls = 0;
    net.state = V2G_NET_TCP_CONNECT;
    v2g_deframe_init(&df);
    net_now = now_ms;
    v2g_stack_tcp_connect(secc_ip, secc_port);   /* lwIP tcp_connect emits the SYN */
}

void v2g_net_tcp_connected(uint32_t now_ms)
{
    /* connected-cb 0x08060ACE: idle reset + event notify(1); state4 TLS decision -> handshake/est. */
    if (net.state != V2G_NET_TCP_CONNECT) return;
    net.tcp_connected = 1;
    net.idle_polls = 0;
    net.last_rx = now_ms;
    net_now = now_ms;
    if (net.use_tls) {
        net.state = V2G_NET_TLS_HANDSHAKE;
        /* mbedTLS setup 0x080604D2: config + CA chain (ca_store) + authmode 2 + bio + rng. */
        if (v2g_stack_tls_setup(ca_store_get()) != 0) { v2g_net_tcp_closed(); return; }
        int r = v2g_stack_tls_handshake();   /* drives ClientHello.. until WANT_READ/done/error */
        if (r == 0) { net.tls_done = 1; net.state = V2G_NET_ESTABLISHED; }
        else if (r < 0) { v2g_net_tcp_closed(); }
    } else {
        net.state = V2G_NET_ESTABLISHED;     /* plain mode1 */
    }
}

void v2g_net_tcp_closed(void)
{
    net.tcp_connected = 0;
    net.state = V2G_NET_CLOSED;
    net.mode = V2G_NET_MODE_NONE;
    v2g_stack_tcp_close();
    v2g_stack_tls_free();
}

void v2g_net_step(uint32_t now_ms)
{
    net_now = now_ms;
    v2g_stack_poll(now_ms);   /* lwIP tcp_tmr/nd6_tmr/ip6_reass_tmr + TLS app-data drain */
    switch (net.state) {
    case V2G_NET_TCP_CONNECT:
        if ((uint32_t)(now_ms - net.ts_connect) > V2G_TCP_CONNECT_TIMEOUT_MS)
            v2g_net_tcp_closed();
        break;
    case V2G_NET_TLS_HANDSHAKE: {
        /* state7 handshake-progress 0x0806058C: drive mbedTLS (records arrive via the rx ring). */
        int r = v2g_stack_tls_handshake();
        if (r == 0) { net.tls_done = 1; net.state = V2G_NET_ESTABLISHED; }
        else if (r < 0) { v2g_net_tcp_closed(); }
        else if ((uint32_t)(now_ms - net.ts_connect) > V2G_SEND_CAP_MS)
            v2g_net_tcp_closed();
        break;
    }
    case V2G_NET_ESTABLISHED:
        /* poll_cb 0x08060A58: idle >= 300 polls without incoming data -> tcp_close. */
        net.idle_polls++;
        if (net.idle_polls >= V2G_TCP_IDLE_CLOSE_POLLS)
            v2g_net_tcp_closed();
        break;
    default:
        break;
    }
}

/* ---- EXI dispatch + trace ring ---- */

void v2g_net_trace_feed(const uint8_t *frame, uint16_t len, uint32_t tick)
{
    uint8_t slot = (uint8_t)(net.trace_idx & 0x0Fu);
    net.trace_idx++;
    uint8_t *s = trace_ring[slot];
    s[0] = (uint8_t)tick; s[1] = (uint8_t)(tick >> 8);
    s[2] = (uint8_t)(tick >> 16); s[3] = (uint8_t)(tick >> 24);
    uint16_t n = (len > 124u) ? 124u : len;
    cp(s + 4, frame, n);
}

int v2g_net_exi_dispatch(const uint8_t *frame, uint16_t len, uint32_t now_ms)
{
    /* 0x08020224: v2gtp_parse (type 0x8001 EXI), trace feed, live path -> ccs2_rx_exi. */
    uint16_t plen;
    uint16_t type = v2gtp_parse(frame, len, &plen);
    v2g_net_trace_feed(frame, len, now_ms);
    if (type == V2GTP_TYPE_EXI) {
        net.rx_frames++;
        return ccs2_rx_exi(frame, len, now_ms);
    }
    return 0;
}

static void deframe_cb(const uint8_t *frame, uint16_t len, void *arg)
{
    uint32_t now_ms = *(const uint32_t *)arg;
    v2g_net_exi_dispatch(frame, len, now_ms);
}

/* ---- RX entry ---- */

void v2g_net_rx_ethernet(const uint8_t *frame, uint16_t len, uint32_t now_ms)
{
    /* ethernet_input 0x0809D914 -> ip6_input 0x0809B88E -> udp/tcp/icmp6 (lwIP demux). UDP ->
     * stack_udp_recv_cb -> sdp_rx; TCP -> stack_app_recv_cb -> deframe -> EXI; ICMPv6 -> lwIP nd6. */
    net_now = now_ms;
    v2g_stack_rx_ethernet(frame, len);
}

/* ---- TX entry ---- */

int v2g_net_udp_send(const uint8_t *v2gtp, uint16_t len)
{
    /* SDP request over UDP multicast ff02::1:15118 (lwIP udp_sendto -> ip6_output_if ->
     * ethip6_output mcast 33:33 -> netif linkoutput -> qca7005_frame_send). */
    int r = v2g_stack_udp_send(v2gtp, len);
    if (r > 0) net.tx_frames++;
    return r;
}

int v2g_net_tcp_send(const uint8_t *v2gtp, uint16_t len, uint32_t now_ms)
{
    /* send router 0x08020338: mode1 plain (tcp_write), mode2 TLS (ssl_write). lwIP handles
     * seq/ack/retransmit + ND6 MAC resolution (queues the segment until the neighbor resolves). */
    if (net.state != V2G_NET_ESTABLISHED) return -1;
    net_now = now_ms;
    int r;
    if (net.mode == V2G_NET_MODE_TLS) r = v2g_stack_tls_write(v2gtp, len);
    else                            r = v2g_stack_tcp_send(v2gtp, len);
    if (r < 0) return r;
    net.tx_frames++;
    v2g_net_trace_feed(v2gtp, len, now_ms);
    return (int)len;
}
