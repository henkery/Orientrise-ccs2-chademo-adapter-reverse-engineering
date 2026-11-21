/* v2g_net.c — V2G network transport (REPORT §5.9, Agent G/H / analyze94). See v2g_net.h.
 * Faithful INERT replica of the C013 live IPv6/UDP/TCP + mbedTLS transport glue + wire framing.
 * Communication only — NO power-stage GPIO. The lwIP TCP reliability + mbedTLS crypto are gated
 * third-party stacks represented by hooks (as the RTOS is by the bare-metal loop). Pure logic
 * host-tested (test_v2g_net.c). Hand-rolled loops (freestanding, no libc mem*). */
#include "v2g_net.h"
#include "v2gtp.h"
#include "sdp.h"
#include "ccs2.h"
#include "nd6.h"

static v2g_net_t net;
static v2g_net_eth_send_fn eth_send;
static v2g_net_tls_wrap_fn tls_wrap;
static v2g_deframe_t df;
static uint8_t tx_buf[1518];
static uint8_t tls_buf[V2G_SSL_RECORD_BUF_SIZE];
static uint8_t trace_ring[16][128];   /* diagnostic TRACE buffer (0x20001FEC) */
static uint8_t local_mac[6];          /* adapter Ethernet src MAC (QCA7005 PIB MAC; netif hwaddr) */

static void z(uint8_t *p, uint16_t n) { for (uint16_t i = 0; i < n; i++) p[i] = 0; }
static void cp(uint8_t *d, const uint8_t *s, uint16_t n) { for (uint16_t i = 0; i < n; i++) d[i] = s[i]; }
static void put16be(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32be(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
                                            p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static uint16_t get16be(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }

/* ---- pure wire helpers ---- */

void v2g_net_ipv6_linklocal(const uint8_t mac[6], uint8_t out[16])
{
    /* 0x08090D68: fe80::/64 + modified-EUI-64 IID [hw0^2,hw1,hw2,FF,FE,hw3,hw4,hw5]. */
    z(out, 16);
    out[0] = 0xFE; out[1] = 0x80;                 /* fe80:: prefix (addr[0]=0x000080fe LE) */
    out[8]  = (uint8_t)(mac[0] ^ 0x02u);          /* universal/local bit flipped */
    out[9]  = mac[1];
    out[10] = mac[2];
    out[11] = 0xFF;                               /* EUI-64 mid bytes */
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
    /* 0x0809BBEC ip6_output_if: vtf=htonl(0x60000000|tos<<20), plen=htons(payload_len),
     * nexth@6, hoplim@7, src@8 (16B), dest@24 (16B). */
    put32be(out, 0x60000000u);                    /* version 6, traffic class/flow label 0 */
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
    if ((hdr[0] >> 4) != V2G_IP6_VERSION) return 0;   /* ip6_input version==6 check */
    if (payload_len) *payload_len = get16be(hdr + 4);
    if (next_hdr) *next_hdr = hdr[6];
    return 1;
}

uint16_t v2g_net_udp_build(uint8_t *out, uint16_t src_port, uint16_t dst_port, uint16_t payload_len)
{
    /* 0x809028A udp_sendto_if_src: src@0, dest@2, len@4 (=payload+8), chksum@6 (placeholder 0;
     * the pseudo-header checksum is computed by v2g_net_ip6_pseudo_chksum over the full UDP datagram). */
    put16be(out, src_port);
    put16be(out + 2, dst_port);
    put16be(out + 4, (uint16_t)(payload_len + V2G_UDP_HDR_LEN));
    put16be(out + 6, 0);
    return V2G_UDP_HDR_LEN;
}

uint16_t v2g_net_tcp_build(uint8_t *out, uint16_t src_port, uint16_t dst_port, uint32_t seq,
                           uint32_t ack, uint8_t flags, uint16_t window)
{
    /* 0x8092A6E tcp_output_segment: src@0, dest@2, seq=htonl(snd_nxt)@4, ack@8, data-offset=5
     * (high nibble of @12), flags@13, window=htons(rcv_wnd)@14, chksum@16 (placeholder), urgent@18. */
    put16be(out, src_port);
    put16be(out + 2, dst_port);
    put32be(out + 4, seq);
    put32be(out + 8, ack);
    out[12] = (uint8_t)((V2G_TCP_HDR_LEN / 4u) << 4);   /* data offset = 5 words = 20 bytes */
    out[13] = flags;
    put16be(out + 14, window);
    put16be(out + 16, 0);
    put16be(out + 18, 0);
    return V2G_TCP_HDR_LEN;
}

uint16_t v2g_net_inet_chksum(const uint8_t *buf, uint16_t len)
{
    /* 0x08098CAC: one's-complement 16-bit sum, fold carries, complement. */
    uint32_t sum = 0;
    uint16_t i = 0;
    for (; (uint16_t)(i + 1) < len; i += 2)
        sum += (uint32_t)(((uint16_t)buf[i] << 8) | buf[i + 1]);
    if (i < len) sum += (uint32_t)((uint16_t)buf[i] << 8);   /* odd trailing byte, high */
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

uint16_t v2g_net_ip6_pseudo_chksum(const uint8_t src[16], const uint8_t dst[16],
                                   uint8_t next_hdr, const uint8_t *payload, uint16_t payload_len)
{
    /* IPv6 pseudo-header: src[16] + dst[16] + upper-layer-packet-length[4 BE] + zero[3] +
     * next-header[1], then the payload (UDP/TCP datagram incl. its header). proto 17/6. */
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
    return c ? c : 0xFFFFu;   /* UDP: computed 0 transmitted as 0xFFFF (RFC 2460) */
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
    /* 0x0809D914 ethernet_input reads ethhdr->type via ldrh LE (byte-swapped: IPv6 wire 86 DD ->
     * LE 0xDD86). This replica normalizes to the WIRE type for downstream compares. */
    if (len < V2G_ETH_HDR_LEN) return 0;
    return get16be(frame + 12);
}

/* ---- V2GTP stream deframe ---- */

void v2g_deframe_init(v2g_deframe_t *df) { df->len = 0; }

uint16_t v2g_deframe_push(v2g_deframe_t *df, const uint8_t *data, uint16_t len,
                          v2g_deframe_cb cb, void *arg)
{
    /* Accumulate the TCP byte stream; extract complete V2GTP frames. dispatch 0x08020224:
     * framelen = rev([buf+4]) + 8 (BE payload length + 8-byte header). Partial trailing bytes
     * are retained for the next push. */
    uint16_t frames = 0;
    for (uint16_t i = 0; i < len; i++) {
        if (df->len < V2G_DEFRAME_BUF_SIZE) df->buf[df->len++] = data[i];
        else { df->len = 0; }   /* overflow guard: reset (stock bound 8509) */
        /* try to extract a complete frame whenever we have at least the 8-byte header */
        while (df->len >= V2GTP_HDR_LEN) {
            /* header magic check distinguishes an invalid header (resync) from a merely partial
             * frame (wait for more bytes). v2gtp_parse returns 0 for BOTH, so it must not be used
             * to decide resync here. */
            if (df->buf[0] != V2GTP_VER || df->buf[1] != V2GTP_INV) {
                for (uint16_t k = 1; k < df->len; k++) df->buf[k - 1] = df->buf[k];
                df->len--;
                continue;
            }
            uint32_t l = ((uint32_t)df->buf[4] << 24) | ((uint32_t)df->buf[5] << 16) |
                         ((uint32_t)df->buf[6] << 8) | (uint32_t)df->buf[7];
            uint32_t framelen32 = l + V2GTP_HDR_LEN;
            if (framelen32 > V2G_DEFRAME_BUF_SIZE) {
                /* bogus length (can never complete in this buffer): resync one byte */
                for (uint16_t k = 1; k < df->len; k++) df->buf[k - 1] = df->buf[k];
                df->len--;
                continue;
            }
            uint16_t framelen = (uint16_t)framelen32;
            if (df->len < framelen) break;   /* partial frame: wait for more bytes */
            if (cb) cb(df->buf, framelen, arg);
            frames++;
            /* shift remaining bytes down */
            uint16_t rem = (uint16_t)(df->len - framelen);
            for (uint16_t k = 0; k < rem; k++) df->buf[k] = df->buf[framelen + k];
            df->len = rem;
        }
    }
    return frames;
}

/* ---- TLS decision + config ---- */

uint8_t v2g_net_tls_decision(uint8_t secc_security)
{
    /* state4 0x080207BC: cbz [ctx+0x23] -> TLS branch (state6 mbedTLS setup). TLS iff byte==0.
     * Matches the ISO15118-2/DIN70121 SDP wire encoding 0x00=TLS / 0x10=No-TLS. CORRECTED: the
     * prior sdp.c use_tls (!=0) + firmware log labels were inverted. */
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
    nd6_init();   /* IPv6 neighbor cache (replaces the gated ND6 hook; Agent N) */
    /* default Ethernet src MAC template (0x080AFDCC); overridden by the PIB MAC via set_local_mac. */
    local_mac[0] = 0xFE; local_mac[1] = 0xFF; local_mac[2] = 0xFE;
    local_mac[3] = 0xFF; local_mac[4] = 0x00; local_mac[5] = 0x01;
}

void v2g_net_set_eth_send(v2g_net_eth_send_fn fn) { eth_send = fn; nd6_set_send(fn); }
void v2g_net_set_tls_wrap(v2g_net_tls_wrap_fn fn) { tls_wrap = fn; }
void v2g_net_set_local_mac(const uint8_t mac[6])
{
    /* ethernetif_init 0x08093202 (from_mac=1): netif hwaddr = PIB MAC; then
     * netif_create_ip6_linklocal_address 0x08090D68 derives fe80::/64 + modified-EUI-64. */
    cp(local_mac, mac, 6);
    v2g_net_ipv6_linklocal(mac, net.local_ip);
    nd6_set_local(net.local_ip, mac);   /* ND6 own address (DAD target match) + SLLA/TLLA source */
}
const v2g_net_t *v2g_net_get(void) { return &net; }

void v2g_net_start_tcp(const uint8_t secc_ip[16], uint16_t secc_port, uint8_t secc_security,
                       uint32_t now_ms)
{
    /* state3 0x0802070E: UDP close + TCP connect (pcb 0x200009A8), arm timer 30000. The TLS
     * decision (state4) is evaluated up front from the SECC security byte. */
    cp(net.secc_ip, secc_ip, 16);
    net.secc_port = secc_port;
    net.use_tls = v2g_net_tls_decision(secc_security);
    net.mode = net.use_tls ? V2G_NET_MODE_TLS : V2G_NET_MODE_PLAIN;
    net.tcp_connected = 0;
    net.tls_done = net.use_tls ? 0u : 1u;   /* plain: no handshake needed */
    net.ts_connect = now_ms;
    net.last_rx = now_ms;
    net.idle_polls = 0;
    net.state = V2G_NET_TCP_CONNECT;
    v2g_deframe_init(&df);
    /* TCP connect is the gated lwIP reliability layer (SYN/ACK); the connected event arrives via
     * v2g_net_tcp_connected (stock connected-cb 0x08060ACE -> event notify(1)). */
}

void v2g_net_tcp_connected(uint32_t now_ms)
{
    /* connected-cb 0x08060ACE: idle reset + event notify(1). Then state4 TLS decision:
     * TLS -> handshake (state6/7); plain -> established (mode1). */
    if (net.state != V2G_NET_TCP_CONNECT) return;
    net.tcp_connected = 1;
    net.idle_polls = 0;
    net.last_rx = now_ms;
    if (net.use_tls) {
        net.state = V2G_NET_TLS_HANDSHAKE;   /* mbedTLS handshake (gated crypto hook) */
    } else {
        net.state = V2G_NET_ESTABLISHED;     /* plain mode1 */
    }
}

void v2g_net_tcp_closed(void)
{
    /* err cb 0x08060A44 / idle poll close: clear pcb + event notify(0). */
    net.tcp_connected = 0;
    net.state = V2G_NET_CLOSED;
    net.mode = V2G_NET_MODE_NONE;
}

void v2g_net_step(uint32_t now_ms)
{
    switch (net.state) {
    case V2G_NET_TCP_CONNECT:
        /* state3 timer 30000: connect timeout -> closed. */
        if ((uint32_t)(now_ms - net.ts_connect) > V2G_TCP_CONNECT_TIMEOUT_MS)
            v2g_net_tcp_closed();
        break;
    case V2G_NET_TLS_HANDSHAKE:
        /* state7 handshake-progress 0x0806058C: the mbedTLS handshake is the gated crypto hook.
         * Inert replica: handshake completes when tls_done is set (bench injection / hook). The
         * 5000ms handshake timeout (bio ctx+0x18) applies. */
        if (net.tls_done) net.state = V2G_NET_ESTABLISHED;   /* state8 mode2 -> state9 ssl_read */
        else if ((uint32_t)(now_ms - net.ts_connect) > V2G_SEND_CAP_MS)
            v2g_net_tcp_closed();
        break;
    case V2G_NET_ESTABLISHED:
        /* poll_cb 0x08060A58: idle >= 300 polls without incoming data -> tcp_close. The 100Hz
         * loop calls step each 10ms; idle_polls increments per step, reset on RX. */
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
    /* 0x08020194: slot = idx & 0xf; addr = base + (slot<<7); 4B LE tick prefix; frame capped 124B.
     * Diagnostic TRACE only — the live RX path bypasses the ring (drained at shutdown 0xf4). */
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
    /* 0x08020224: v2gtp_parse (type 0x180=0x8001 EXI), trace feed, then live path -> session-rx
     * entry 0x0802E76A -> session RX engine 0x080353B2 -> decode wrapper 0x08033C24 (=ccs2_rx_exi). */
    uint16_t plen;
    uint16_t type = v2gtp_parse(frame, len, &plen);
    v2g_net_trace_feed(frame, len, now_ms);   /* diagnostic trace (RX feed) */
    if (type == V2GTP_TYPE_EXI) {
        net.rx_frames++;
        return ccs2_rx_exi(frame, len, now_ms);
    }
    return 0;   /* type 0x1c0 (0x08020316) / other: not an EXI Res frame */
}

/* deframe callback: dispatch each complete V2GTP frame. arg = pointer to now_ms. */
static void deframe_cb(const uint8_t *frame, uint16_t len, void *arg)
{
    uint32_t now_ms = *(const uint32_t *)arg;
    v2g_net_exi_dispatch(frame, len, now_ms);
}

/* ---- RX entry ---- */

void v2g_net_rx_ethernet(const uint8_t *frame, uint16_t len, uint32_t now_ms)
{
    /* ethernet_input 0x0809D914 -> ip6_input 0x0809B88E -> udp_input/tcp_input. */
    if (len < V2G_ETH_HDR_LEN) return;
    uint16_t et = v2g_net_ethertype(frame, len);
    if (et != V2G_ETHTYPE_IPV6) return;   /* MME->slac (ccs2_rx); IPv4/ARP not used by EVCC */
    const uint8_t *ip6 = frame + V2G_ETH_HDR_LEN;
    uint16_t ip6_len = (uint16_t)(len - V2G_ETH_HDR_LEN);
    uint16_t payload_len; uint8_t nh;
    if (!v2g_net_ip6_parse(ip6, ip6_len, &payload_len, &nh)) return;
    const uint8_t *payload = ip6 + V2G_IP6_HDR_LEN;
    uint16_t avail = (uint16_t)(ip6_len - V2G_IP6_HDR_LEN);
    if (payload_len > avail) payload_len = avail;

    if (nh == V2G_IP6_NH_UDP) {
        /* udp_input 0x809002C: port match -> recv_cb 0x08060966 -> SDP SM. SDP response payload. */
        if (payload_len < V2G_UDP_HDR_LEN) return;
        uint16_t udp_plen = (uint16_t)(get16be(payload + 4) - V2G_UDP_HDR_LEN);
        if (udp_plen > (uint16_t)(payload_len - V2G_UDP_HDR_LEN))
            udp_plen = (uint16_t)(payload_len - V2G_UDP_HDR_LEN);
        sdp_rx(payload + V2G_UDP_HDR_LEN, udp_plen);
        net.last_rx = now_ms; net.idle_polls = 0;
    } else if (nh == V2G_IP6_NH_TCP) {
        /* tcp_input 0x8099BA6 -> recv_cb 0x08060A82 -> SM + tcp_recved. Deframe the TCP byte
         * stream into V2GTP frames -> EXI dispatch -> ccs2_rx_exi. */
        if (payload_len < V2G_TCP_HDR_LEN) return;
        uint16_t doff = (uint16_t)((payload[12] >> 4) * 4u);
        if (doff < V2G_TCP_HDR_LEN || doff > payload_len) return;
        uint16_t tcp_plen = (uint16_t)(payload_len - doff);
        v2g_deframe_push(&df, payload + doff, tcp_plen, deframe_cb, &now_ms);
        net.last_rx = now_ms; net.idle_polls = 0;
    } else if (nh == V2G_IP6_NH_ICMP6) {
        /* icmp6_input 0x0809B3D0 -> nd6_input 0x0809C926 (NS135/NA136/RA134). IPv6 src@+8, dst@+24.
         * ND6 resolves the SECC link-local -> MAC for unicast TX (replaces the gated ND6 hook). */
        nd6_input(payload, payload_len, ip6 + 8, ip6 + 24);
    }
    /* No-Next (59): dropped (ip6_input demux). */
}

/* ---- TX entry ---- */

int v2g_net_udp_send(const uint8_t *v2gtp, uint16_t len)
{
    /* SDP request over UDP multicast ff02::1:15118. udp_sendto_if_src 0x809028A (UDP hdr +
     * pseudo chksum proto 17) -> ip6_output_if -> ethip6_output (mcast MAC 33:33) -> QCA write. */
    if (len == 0 || (uint16_t)(len + V2G_UDP_HDR_LEN + V2G_IP6_HDR_LEN + V2G_ETH_HDR_LEN) > sizeof tx_buf)
        return -1;
    uint8_t dst[16]; z(dst, 16); dst[0] = 0xFF; dst[1] = 0x02; dst[15] = 0x01;   /* ff02::1 */
    uint8_t mcast[6]; v2g_net_ipv6_mcast_mac(dst, mcast);
    uint16_t udp_len = (uint16_t)(len + V2G_UDP_HDR_LEN);
    /* Ethernet + IPv6 + UDP + payload. src MAC = adapter PIB MAC (netif hwaddr, local_mac). */
    uint16_t o = v2g_net_eth_build(tx_buf, mcast, local_mac, V2G_ETHTYPE_IPV6);
    o = (uint16_t)(o + v2g_net_ip6_build(tx_buf + o, udp_len, V2G_IP6_NH_UDP, 255, net.local_ip, dst));
    uint16_t udp_off = o;
    o = (uint16_t)(o + v2g_net_udp_build(tx_buf + o, net.local_port ? net.local_port : V2G_UDP_SRC_PORT_MIN,
                                         SDP_PORT, len));
    cp(tx_buf + o, v2gtp, len);
    o = (uint16_t)(o + len);
    /* UDP checksum over the IPv6 pseudo-header + UDP datagram (proto 17). */
    uint16_t c = v2g_net_ip6_pseudo_chksum(net.local_ip, dst, V2G_IP6_NH_UDP, tx_buf + udp_off, udp_len);
    put16be(tx_buf + udp_off + 6, c);
    if (eth_send) eth_send(tx_buf, o);
    net.tx_frames++;
    return (int)len;
}

int v2g_net_tcp_send(const uint8_t *v2gtp, uint16_t len, uint32_t now_ms)
{
    /* EXI V2GTP frame over the established TCP transport. send router 0x08020338: mode1 plain
     * (raw tcp_write 0x08060B44), mode2 TLS (ssl_write 0x0808F950 -> record wrap -> tcp_write).
     * TCP reliability (seq/ack/retransmit) is the gated lwIP layer; the replica builds the wire
     * header mechanism (tcp_output_segment 0x8092A6E) + IPv6/Ethernet framing. */
    (void)now_ms;
    if (net.state != V2G_NET_ESTABLISHED) return -1;
    const uint8_t *app = v2gtp;
    uint16_t app_len = len;
    if (net.mode == V2G_NET_MODE_TLS && tls_wrap) {
        int n = tls_wrap(v2gtp, len, tls_buf, sizeof tls_buf);   /* mbedTLS ssl_write (gated crypto) */
        if (n <= 0) return n;
        app = tls_buf; app_len = (uint16_t)n;
    }
    if ((uint16_t)(app_len + V2G_TCP_HDR_LEN + V2G_IP6_HDR_LEN + V2G_ETH_HDR_LEN) > sizeof tx_buf)
        return -1;
    /* Ethernet dst MAC: multicast if SECC ip multicast, else ND6 neighbor lookup (ethip6_output
     * 0x0809B35C -> 0x0809D5D6). If ND6 has not resolved the SECC MAC the packet is queued + an NS
     * sent (nd6_lookup returns 0); defer this send until the neighbor is REACHABLE. */
    uint8_t dstmac[6];
    if (net.secc_ip[0] == 0xFFu) v2g_net_ipv6_mcast_mac(net.secc_ip, dstmac);
    else if (!nd6_lookup(net.secc_ip, dstmac)) return -1;
    uint16_t tcp_len = (uint16_t)(app_len + V2G_TCP_HDR_LEN);
    uint16_t o = v2g_net_eth_build(tx_buf, dstmac, local_mac, V2G_ETHTYPE_IPV6);
    o = (uint16_t)(o + v2g_net_ip6_build(tx_buf + o, tcp_len, V2G_IP6_NH_TCP, 255, net.local_ip, net.secc_ip));
    uint16_t tcp_off = o;
    /* seq/ack: lwIP snd_nxt/rcv_nxt are gated; placeholder 0 (wire mechanism verified). flags
     * ACK|PSH = 0x18, window = rcv_wnd (placeholder 0xa02d stock control-segment window). */
    o = (uint16_t)(o + v2g_net_tcp_build(tx_buf + o, net.tcp_local_port ? net.tcp_local_port : V2G_UDP_SRC_PORT_MIN,
                                         net.secc_port, 0, 0, 0x18u, 0xa02du));
    cp(tx_buf + o, app, app_len);
    o = (uint16_t)(o + app_len);
    uint16_t c = v2g_net_ip6_pseudo_chksum(net.local_ip, net.secc_ip, V2G_IP6_NH_TCP, tx_buf + tcp_off, tcp_len);
    put16be(tx_buf + tcp_off + 16, c);
    if (eth_send) eth_send(tx_buf, o);
    net.tx_frames++;
    v2g_net_trace_feed(v2gtp, len, now_ms);   /* TX trace feed (send router 0x08020338) */
    return (int)len;
}