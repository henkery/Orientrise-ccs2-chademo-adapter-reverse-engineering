/* v2g_net.h — V2G network transport: IPv6/UDP/TCP wire framing + EUI-64 addressing + V2GTP
 * stream deframe + transport connection SM + TLS decision/config + EXI dispatch (REPORT §5.9,
 * Agent G/H / analyze94).
 *
 * Faithful INERT replica of the C013 live UDP/TCP/IPv6 + mbedTLS transport that carries the CCS2
 * EVCC session between the QCA7005 PLC Ethernet transport (qca7005.c) and the DIN EXI session
 * (ccs2_rx_exi). Byte-derived from the lwIP raw-API plumbing + the adapter's transport glue:
 *
 *   IPv6 link-local  netif_create_ip6_linklocal_address 0x08090D68 : fe80::/64 + modified-EUI-64
 *                    from the QCA7005 PIB MAC (IID = [hw0^2,hw1,hw2,FF,FE,hw3,hw4,hw5]).
 *   RX demux         ethernet_input 0x0809D914 (EtherType, LE byte-swapped: IPv6 0xDD86) ->
 *                    ip6_input 0x0809B88E (next-header 6=TCP/17=UDP/58=ICMPv6/59=drop) ->
 *                    udp_input 0x809002C (port match -> recv_cb -> SDP SM) / tcp_input 0x8099BA6
 *                    (recv_cb 0x08060A82 -> SM + tcp_recved).
 *   TX framing       udp_sendto_if_src 0x809028A (UDP hdr + inet_chksum_pseudo proto 17) /
 *                    tcp_output_segment 0x8092A6E (seq=htonl(snd_nxt), window=htons(rcv_wnd),
 *                    chksum proto 6) -> ip6_output_if 0x0809BBEC (40B hdr) -> ethip6_output
 *                    0x0809B35C (multicast 33:33:dst[12..15]) -> ethernet_output -> QCA write.
 *   V2GTP deframe    EXI dispatch 0x08020224 : v2gtp_parse 0x080212C2 (type 0x180=0x8001 EXI),
 *                    framelen = rev([buf+4]) + 8 ; live path -> session-rx entry 0x0802E76A ->
 *                    session RX engine 0x080353B2 -> decode wrapper 0x08033C24 (= ccs2_rx_exi).
 *   transport SM     0x08020468 (ctx 0x20000BBC) states 3..9 : UDP close + TCP connect (pcb
 *                    0x200009A8, timer 30000) -> connected event -> TLS decision -> handshake ->
 *                    established. TCP idle close at 300 polls (poll_cb 0x08060A58).
 *   TLS decision     state4 0x080207BC : TLS iff SECC security byte == 0 (CORRECTED — matches the
 *                    ISO15118-2/DIN70121 SDP wire encoding 0x00=TLS / 0x10=No-TLS; the firmware log
 *                    labels + the prior sdp.c use_tls were inverted). mode1=PLAIN (raw tcp_write
 *                    0x08060B44), mode2=TLS (ssl_write 0x0808F950).
 *   mbedTLS config   setup 0x080604D2 : ssl ctx 0x20020314 (220B), 2x8509B in/out record buffers,
 *                    cipher list 0x080B0668 = {0xC023 ECDHE-ECDSA-AES128-CBC-SHA256, 0xC025
 *                    ECDH-ECDSA-AES128-CBC-SHA256, 0}, authmode 2 = VERIFY_REQUIRED, CA chain from
 *                    the PnC cert store. Record wrap (5B header + encrypt) in ssl_write_real
 *                    0x0808E94A; bio f_send 0x0806043E -> tcp_write, f_recv 0x08060414 -> memcpy.
 *   send router      0x08020338 : mode dispatch + loop-until-all-sent (cap 5000ms, budget 50000ms);
 *                    send entry 0x0802104A TX-pending 0x20002A54 (-6 if pending, cooldown 180ms).
 *   trace ring       0x20001FEC = 16x128B diagnostic TRACE buffer (4B LE tick prefix + <=124B
 *                    frame), fed by dispatch (RX) + send router (TX), drained only at shutdown
 *                    state 0xf4 (log dump). The live RX path BYPASSES the ring.
 *
 * INERT: communication transport only — drives NO power-stage GPIO. The heavy third-party stacks
 * (lwIP TCP reliability: SYN/ACK/retransmit/congestion; mbedTLS crypto: ECDHE/AES/SHA256/X509) are
 * NOT reimplemented bare-metal — they are represented by hooks (tcp_connect/tcp_write/tls_wrap),
 * exactly as the stock RTOS is represented by the bare-metal single loop. The replica faithfully
 * reproduces the adapter's transport glue + the byte-level wire framing + the protocol decisions
 * (addressing, demux, deframe, TLS decision, mode mapping, timers, EXI dispatch). Pure logic is
 * host-unit-tested (test_v2g_net.c); the live modem I/O is behind qca7005_frame_send + RX injection.
 */
#ifndef V2G_NET_H
#define V2G_NET_H
#include <stdint.h>

/* ---- EtherType / IPv6 next-header constants (wire values) ---- */
#define V2G_ETHTYPE_IPV4   0x0800u
#define V2G_ETHTYPE_ARP    0x0806u
#define V2G_ETHTYPE_IPV6   0x86DDu
#define V2G_ETHTYPE_MME    0x88E1u   /* HomePlug AV (SLAC) — handled by slac, not here */
#define V2G_IP6_NH_TCP     6u
#define V2G_IP6_NH_UDP     17u
#define V2G_IP6_NH_ICMP6   58u
#define V2G_IP6_NH_NONEXT  59u
#define V2G_IP6_HDR_LEN    40u
#define V2G_UDP_HDR_LEN    8u
#define V2G_TCP_HDR_LEN    20u
#define V2G_ETH_HDR_LEN    14u
#define V2G_ETH_PAD_SIZE   2u        /* stock ETH_PAD_SIZE (pbuf offset) */
#define V2G_IP6_VERSION    6u

/* ---- TLS config (mbedTLS setup 0x080604D2, cipher list 0x080B0668) ---- */
#define V2G_TLS_CIPHER_ECDHE_ECDSA_AES128_CBC_SHA256  0xC023u
#define V2G_TLS_CIPHER_ECDH_ECDSA_AES128_CBC_SHA256   0xC025u
#define V2G_TLS_AUTHMODE_VERIFY_REQUIRED              2u   /* conf_authmode bfi bits[3:2] */
#define V2G_SSL_CTX_SIZE                              0xDCu   /* 220 B mbedtls_ssl_context */
#define V2G_SSL_RECORD_BUF_SIZE                       0x213Du /* 8509 B in_buf/out_buf */
#define V2G_TLS_MAX_CONTENT                           (V2G_SSL_RECORD_BUF_SIZE - 13u) /* ~8496 */

/* ---- transport timers (ms; TIM7 1ms tick; TCP idle in poll units) ---- */
#define V2G_TCP_CONNECT_TIMEOUT_MS  30000u  /* state3 arm 0x7530 */
#define V2G_TCP_IDLE_CLOSE_POLLS    300u    /* poll_cb 0x08060A58 idle >= 0x12c */
#define V2G_SEND_CAP_MS             5000u   /* router per-call cap 0x1388 */
#define V2G_SEND_BUDGET_MS          50000u  /* router total budget 0xc350 */
#define V2G_SEND_COOLDOWN_MS        180u    /* TX-pending cooldown 0xb4 */
#define V2G_UDP_SRC_PORT_MIN        0xC000u /* ephemeral ubfx(rand,0,14)+0xC000 */

/* ---- transport connection state (the network carriage around the SDP/DIN SM) ---- */
typedef enum {
    V2G_NET_IDLE = 0,        /* no transport; awaiting SDP SECC resolution        */
    V2G_NET_UDP_DISCOVERY,   /* SDP request/response over UDP multicast           */
    V2G_NET_TCP_CONNECT,     /* SECC found; TCP connect pending (timer 30000)     */
    V2G_NET_TLS_HANDSHAKE,   /* TLS iff secc_security==0; mbedTLS handshake       */
    V2G_NET_ESTABLISHED,     /* plain or TLS session established; EXI rx/tx       */
    V2G_NET_CLOSED           /* TCP idle/error/close                              */
} v2g_net_state_t;

/* transport mode (ctx+0x29): 1=PLAIN raw tcp_write, 2=TLS ssl_write (CORRECTED mapping). */
#define V2G_NET_MODE_NONE   0u
#define V2G_NET_MODE_PLAIN  1u
#define V2G_NET_MODE_TLS    2u

/* TX hooks (NULL = inert, frame recorded only). The live modem I/O is qca7005_frame_send. */
typedef void (*v2g_net_eth_send_fn)(const uint8_t *frame, uint16_t len);
/* TLS record wrap hook: wrap plaintext V2GTP into a TLS record (mbedTLS ssl_write). NULL = inert
 * passthrough (plain). The real crypto (ECDHE/AES/SHA256) is the gated third-party stack. */
typedef int (*v2g_net_tls_wrap_fn)(const uint8_t *in, uint16_t in_len, uint8_t *out, uint16_t out_cap);

typedef struct {
    uint8_t  state;            /* v2g_net_state_t                                 */
    uint8_t  mode;             /* V2G_NET_MODE_NONE/PLAIN/TLS                     */
    uint8_t  use_tls;          /* 1 iff secc_security == 0 (CORRECTED)            */
    uint8_t  secc_ip[16];      /* SECC IPv6 (network order)                       */
    uint16_t secc_port;        /* SECC TCP port (host order)                      */
    uint8_t  local_ip[16];     /* adapter link-local IPv6 (EUI-64 from PIB MAC)   */
    uint16_t local_port;       /* ephemeral UDP source port (SDP)                 */
    uint16_t tcp_local_port;   /* TCP source port                                 */
    uint32_t ts_connect;       /* TCP connect start (ms)                          */
    uint32_t last_rx;          /* last received data (ms) — idle tracking         */
    uint16_t idle_polls;       /* TCP poll idle counter (close at 300)            */
    uint8_t  tcp_connected;    /* TCP connected event received                    */
    uint8_t  tls_done;         /* TLS handshake complete                          */
    /* TLS config record (inert; mirrors mbedTLS setup 0x080604D2) */
    uint16_t ciphers[2];       /* {0xC023, 0xC025}                                */
    uint8_t  authmode;         /* 2 = VERIFY_REQUIRED                             */
    /* TX-pending (0x20002A54): cooldown-gated send queue */
    uint32_t pend_ts;          /* last send timestamp (ms)                        */
    uint16_t pend_len;         /* queued payload length (0 = none)                */
    /* diagnostic trace ring (0x20001FEC): 16x128B, 4B tick prefix + <=124B frame */
    uint8_t  trace_idx;        /* free-running slot index (&0xf)                  */
    uint32_t rx_frames;        /* EXI frames dispatched to ccs2_rx_exi            */
    uint32_t tx_frames;        /* V2GTP frames sent                               */
} v2g_net_t;

void v2g_net_init(void);
void v2g_net_set_eth_send(v2g_net_eth_send_fn fn);
void v2g_net_set_tls_wrap(v2g_net_tls_wrap_fn fn);
/* Set the adapter MAC (QCA7005 PIB MAC): stores the Ethernet src MAC + derives the link-local
 * IPv6 (netif_create_ip6_linklocal_address 0x08090D68, ethernetif_init from_mac=1). */
void v2g_net_set_local_mac(const uint8_t mac[6]);
const v2g_net_t *v2g_net_get(void);

/* ---- pure, host-testable wire helpers (byte-exact, no hardware) ---- */
/* 0x08090D68: fe80::/64 + modified-EUI-64 IID from the 6-byte PIB MAC. out[16] network order. */
void v2g_net_ipv6_linklocal(const uint8_t mac[6], uint8_t out[16]);
/* 0x0809B35C: IPv6 multicast MAC = 33:33:dst[12..15]. out[6]. */
void v2g_net_ipv6_mcast_mac(const uint8_t dst[16], uint8_t out[6]);
/* 0x0809BBEC: build a 40-byte IPv6 header (vtf=0x60000000, plen BE, nexth, hoplim, src@8, dst@24).
 * Returns 40. payload_len excludes the IPv6 header. */
uint16_t v2g_net_ip6_build(uint8_t *out, uint16_t payload_len, uint8_t next_hdr,
                           uint8_t hop_limit, const uint8_t src[16], const uint8_t dst[16]);
/* Parse a 40-byte IPv6 header. Returns 1 if version==6 and len>=40; writes payload_len/next_hdr. */
int v2g_net_ip6_parse(const uint8_t *hdr, uint16_t len, uint16_t *payload_len, uint8_t *next_hdr);
/* 0x809028A: build an 8-byte UDP header (src/dst/len=payload+8 BE, chksum=0 placeholder). Ret 8. */
uint16_t v2g_net_udp_build(uint8_t *out, uint16_t src_port, uint16_t dst_port, uint16_t payload_len);
/* 0x8092A6E: build a 20-byte TCP header (data-offset=5, seq/ack BE, flags, window BE, chksum=0). */
uint16_t v2g_net_tcp_build(uint8_t *out, uint16_t src_port, uint16_t dst_port, uint32_t seq,
                           uint32_t ack, uint8_t flags, uint16_t window);
/* 0x08098CAC: Internet checksum (one's-complement sum) over buf[0..len). Returns folded u16. */
uint16_t v2g_net_inet_chksum(const uint8_t *buf, uint16_t len);
/* IPv6 pseudo-header checksum for UDP(17)/TCP(6): src/dst/payload_len/next_hdr + payload. */
uint16_t v2g_net_ip6_pseudo_chksum(const uint8_t src[16], const uint8_t dst[16],
                                   uint8_t next_hdr, const uint8_t *payload, uint16_t payload_len);
/* Build a 14-byte Ethernet header (dst[6], src[6], ethertype BE). Returns 14. */
uint16_t v2g_net_eth_build(uint8_t *out, const uint8_t dst[6], const uint8_t src[6], uint16_t ethertype);
/* 0x0809D914: read the wire EtherType from an Ethernet frame (normalizes the stock LE byte-swap).
 * Returns the wire type (0x86DD/0x0800/0x0806/0x88E1) or 0 if len<14. */
uint16_t v2g_net_ethertype(const uint8_t *frame, uint16_t len);

/* ---- V2GTP stream deframe (TCP byte stream -> complete V2GTP frames; dispatch 0x08020224) ---- */
#define V2G_DEFRAME_BUF_SIZE  8509u   /* stock stream buffer bound (0x213D) */
typedef struct {
    uint8_t  buf[V2G_DEFRAME_BUF_SIZE];
    uint16_t len;             /* bytes accumulated so far */
} v2g_deframe_t;
void v2g_deframe_init(v2g_deframe_t *df);
/* Push received TCP bytes; extract every complete V2GTP frame (framelen = BE([buf+4]) + 8) and
 * invoke cb(frame, framelen, arg) per frame. Returns the number of complete frames extracted.
 * Partial trailing bytes are retained for the next push. Mirrors dispatch 0x08020224 deframing. */
typedef void (*v2g_deframe_cb)(const uint8_t *frame, uint16_t len, void *arg);
uint16_t v2g_deframe_push(v2g_deframe_t *df, const uint8_t *data, uint16_t len,
                          v2g_deframe_cb cb, void *arg);

/* ---- TLS decision + config (CORRECTED; state4 0x080207BC / setup 0x080604D2) ---- */
/* TLS iff SECC security byte == 0 (wire 0x00=TLS / 0x10=No-TLS). Returns 1 for TLS. */
uint8_t v2g_net_tls_decision(uint8_t secc_security);

/* ---- transport SM + RX/TX entry points ---- */
/* Begin TCP transport to a resolved SECC (after SDP). Sets use_tls/mode from secc_security. */
void v2g_net_start_tcp(const uint8_t secc_ip[16], uint16_t secc_port, uint8_t secc_security,
                       uint32_t now_ms);
/* Notify the TCP connected event (stock connected-cb 0x08060ACE -> event notify(1)). */
void v2g_net_tcp_connected(uint32_t now_ms);
/* Notify a TCP error/close (err cb 0x08060A44 / idle poll close). */
void v2g_net_tcp_closed(void);
/* Drive the transport one tick (ms): TCP connect timeout, idle close, TLS handshake progress. */
void v2g_net_step(uint32_t now_ms);
/* RX: a received Ethernet frame from the QCA7005 -> EtherType/IPv6/next-header demux -> UDP (SDP)
 * or TCP (deframe -> EXI dispatch -> ccs2_rx_exi). now_ms is the millisecond timestamp. */
void v2g_net_rx_ethernet(const uint8_t *frame, uint16_t len, uint32_t now_ms);
/* EXI dispatch (0x08020224): a complete V2GTP frame -> type 0x8001 -> ccs2_rx_exi (+ trace feed).
 * Returns the ccs2_rx_exi result (EXI_OK / negative) or 0 if not an EXI frame. */
int v2g_net_exi_dispatch(const uint8_t *frame, uint16_t len, uint32_t now_ms);
/* TX: send a V2GTP EXI frame over the established TCP transport (mode1 plain / mode2 TLS wrap),
 * framed TCP/IPv6/Ethernet -> eth_send hook. Returns bytes sent (frame len) or negative error. */
int v2g_net_tcp_send(const uint8_t *v2gtp, uint16_t len, uint32_t now_ms);
/* TX: send an SDP V2GTP frame over UDP multicast (ff02::1:15118), framed UDP/IPv6/Ethernet. */
int v2g_net_udp_send(const uint8_t *v2gtp, uint16_t len);
/* Diagnostic trace-ring feed (0x08020194): record a frame + tick into the 16x128B ring. */
void v2g_net_trace_feed(const uint8_t *frame, uint16_t len, uint32_t tick);

#endif /* V2G_NET_H */