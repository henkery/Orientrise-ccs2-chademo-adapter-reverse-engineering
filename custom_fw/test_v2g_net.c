/* test_v2g_net.c — host unit test for the V2G network transport GLUE (custom_fw/src/v2g_net.c,
 * REPORT §5.9, Agent G/H / analyze94). LIBRARY PIVOT: the live IPv6/ND6/TCP/UDP + TLS stack is now
 * the REAL vendored lwIP 2.1.x + mbedTLS 2.28 (src/v2g_stack.c). This test owns the recovered GLUE
 * that sits ABOVE the stack: the byte-exact reference wire helpers, the V2GTP stream deframe, the
 * EXI dispatch -> ccs2_rx_exi, the TLS decision, and the transport connection SM (connect /
 * handshake / established / idle-close / connect-timeout) + send router. The v2g_stack integration
 * layer is STUBBED + spied here (the real lwIP/mbedTLS stack is validated by test_tls_mbedtls.c +
 * verify_ccs2.py + the firmware build); ccs2_rx_exi / sdp_rx are spied (heavy upper modules unlinked).
 * Build + run:
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_v2g_net \
 *       test_v2g_net.c src/v2g_net.c src/v2gtp.c && ./test_v2g_net' */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "v2g_net.h"
#include "v2gtp.h"
#include "v2g_stack.h"
#include "ca_store.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

/* ---- spies for the gated upper-layer entry points ---- */
static uint8_t  spy_exi[256]; static uint16_t spy_exi_len; static uint32_t spy_exi_ms;
static int      spy_exi_calls;
int ccs2_rx_exi(const uint8_t *frame, uint16_t len, uint32_t now_ms)
{
    spy_exi_calls++;
    spy_exi_len = len; spy_exi_ms = now_ms;
    memcpy(spy_exi, frame, len < sizeof spy_exi ? len : sizeof spy_exi);
    return 0;   /* EXI_OK */
}
static uint8_t  spy_sdp[64]; static uint16_t spy_sdp_len; static int spy_sdp_calls;
void sdp_rx(const uint8_t *buf, uint16_t len)
{
    spy_sdp_calls++;
    spy_sdp_len = len;
    memcpy(spy_sdp, buf, len < sizeof spy_sdp ? len : sizeof spy_sdp);
}

/* ---- stubbed v2g_stack integration layer (spy the glue -> stack wiring) ---- */
static uint8_t stub_mac[6];
static int stub_init_calls, stub_poll_calls, stub_connect_calls;
static uint8_t stub_connect_ip[16]; static uint16_t stub_connect_port;
static int stub_tls_setup_calls, stub_tls_handshake_calls, stub_tls_handshake_ret = 1;
static int stub_tcp_send_calls, stub_tls_write_calls, stub_udp_send_calls;
static int stub_tcp_close_calls, stub_tls_free_calls;
static uint16_t stub_tcp_send_len;
static v2g_stack_connected_fn stub_connected_fn;
static v2g_stack_app_recv_fn stub_recv_fn;
static v2g_stack_closed_fn stub_closed_fn;

void v2g_stack_init(const uint8_t mac[6], v2g_stack_eth_send_fn eth_send)
{ stub_init_calls++; memcpy(stub_mac, mac, 6); (void)eth_send; }
void v2g_stack_set_rng(v2g_stack_rng_fn fn, void *ctx) { (void)fn; (void)ctx; }
void v2g_stack_local_ip(uint8_t out[16]) { v2g_net_ipv6_linklocal(stub_mac, out); }  /* EUI-64, as lwIP */
void v2g_stack_rx_ethernet(const uint8_t *frame, uint16_t len) { (void)frame; (void)len; }
void v2g_stack_poll(uint32_t now_ms) { (void)now_ms; stub_poll_calls++; }
void v2g_stack_set_udp_recv(v2g_stack_udp_recv_fn fn) { (void)fn; }
int  v2g_stack_udp_send(const uint8_t *data, uint16_t len) { (void)data; stub_udp_send_calls++; return (int)len; }
void v2g_stack_set_tcp_cbs(v2g_stack_connected_fn c, v2g_stack_app_recv_fn r, v2g_stack_closed_fn cl)
{ stub_connected_fn = c; stub_recv_fn = r; stub_closed_fn = cl; }
int  v2g_stack_tcp_connect(const uint8_t secc_ip[16], uint16_t port)
{ stub_connect_calls++; memcpy(stub_connect_ip, secc_ip, 16); stub_connect_port = port; return 0; }
int  v2g_stack_tcp_send(const uint8_t *data, uint16_t len)
{ (void)data; stub_tcp_send_calls++; stub_tcp_send_len = len; return (int)len; }
void v2g_stack_tcp_close(void) { stub_tcp_close_calls++; }
int  v2g_stack_tcp_is_connected(void) { return 1; }
int  v2g_stack_tls_setup(const ca_store_t *ca) { (void)ca; stub_tls_setup_calls++; return 0; }
int  v2g_stack_tls_handshake(void) { stub_tls_handshake_calls++; return stub_tls_handshake_ret; }
int  v2g_stack_tls_write(const uint8_t *data, uint16_t len) { (void)data; stub_tls_write_calls++; return (int)len; }
int  v2g_stack_tls_read(uint8_t *out, uint16_t cap) { (void)out; (void)cap; return 0; }
int  v2g_stack_tls_done(void) { return stub_tls_handshake_ret == 0; }
void v2g_stack_tls_free(void) { stub_tls_free_calls++; }
const ca_store_t *ca_store_get(void) { return NULL; }

/* build a minimal valid V2GTP EXI frame (type 0x8001) with an n-byte payload */
static uint16_t mk_exi(uint8_t *b, uint16_t plen)
{
    memset(b, 0, 8 + plen);
    for (uint16_t i = 0; i < plen; i++) b[8 + i] = (uint8_t)(0xA0 + i);
    return v2gtp_encode(b, plen, V2GTP_TYPE_EXI);
}

int main(void)
{
    /* --- IPv6 link-local EUI-64 (0x08090D68): fe80:: + [hw0^2,hw1,hw2,FF,FE,hw3,hw4,hw5] --- */
    uint8_t mac[6] = {0x00, 0xB0, 0x52, 0x00, 0x00, 0x01};   /* QCA default PIB MAC */
    uint8_t ip[16];
    v2g_net_ipv6_linklocal(mac, ip);
    CHECK(ip[0] == 0xFE && ip[1] == 0x80, "link-local prefix fe80::");
    CHECK(ip[2] == 0 && ip[7] == 0, "link-local prefix zero middle");
    CHECK(ip[8] == 0x02, "EUI-64 hw0^2 (0x00^2=0x02)");
    CHECK(ip[9] == 0xB0 && ip[10] == 0x52, "EUI-64 hw1/hw2");
    CHECK(ip[11] == 0xFF && ip[12] == 0xFE, "EUI-64 FF:FE mid");
    CHECK(ip[13] == 0x00 && ip[14] == 0x00 && ip[15] == 0x01, "EUI-64 hw3/hw4/hw5");
    /* universal/local bit flip: a MAC with hw0 bit1 set clears it */
    uint8_t mac2[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    v2g_net_ipv6_linklocal(mac2, ip);
    CHECK(ip[8] == 0x00, "EUI-64 hw0^2 flips bit1 (0x02^2=0x00)");

    /* --- IPv6 multicast MAC (0x0809B35C): 33:33:dst[12..15] --- */
    uint8_t dst[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    uint8_t mmac[6];
    v2g_net_ipv6_mcast_mac(dst, mmac);
    CHECK(mmac[0] == 0x33 && mmac[1] == 0x33, "mcast MAC 33:33 prefix");
    CHECK(mmac[2] == 0 && mmac[5] == 0x01, "mcast MAC dst[12..15]");

    /* --- IPv6 header build/parse (0x0809BBEC) --- */
    uint8_t h[40];
    uint8_t src[16], dst2[16];
    v2g_net_ipv6_linklocal(mac, src);
    memset(dst2, 0, 16); dst2[0] = 0xFE; dst2[1] = 0x80; dst2[15] = 0x02;
    uint16_t n = v2g_net_ip6_build(h, 100, V2G_IP6_NH_TCP, 255, src, dst2);
    CHECK(n == 40, "ip6 header len 40");
    CHECK(h[0] == 0x60, "ip6 version 6 (vtf high nibble)");
    CHECK(h[4] == 0 && h[5] == 100, "ip6 payload len BE 100");
    CHECK(h[6] == 6 && h[7] == 255, "ip6 next-header TCP + hop limit 255");
    CHECK(memcmp(h + 8, src, 16) == 0, "ip6 src @8");
    CHECK(memcmp(h + 24, dst2, 16) == 0, "ip6 dst @24");
    uint16_t plen; uint8_t nh;
    CHECK(v2g_net_ip6_parse(h, 40, &plen, &nh) == 1, "ip6 parse ok");
    CHECK(plen == 100 && nh == 6, "ip6 parse payload/next-header");
    h[0] = 0x40;   /* version 4 -> reject */
    CHECK(v2g_net_ip6_parse(h, 40, &plen, &nh) == 0, "ip6 parse rejects version != 6");
    CHECK(v2g_net_ip6_parse(h, 39, &plen, &nh) == 0, "ip6 parse rejects len < 40");

    /* --- UDP header (0x809028A) --- */
    uint8_t uh[8];
    n = v2g_net_udp_build(uh, 0xC001, 15118, 2);
    CHECK(n == 8, "udp header len 8");
    CHECK(uh[0] == 0xC0 && uh[1] == 0x01, "udp src port BE");
    CHECK(uh[2] == 0x3B && uh[3] == 0x0E, "udp dst port 15118 BE");
    CHECK(uh[4] == 0 && uh[5] == 10, "udp len = payload+8 = 10");

    /* --- TCP header (0x8092A6E) --- */
    uint8_t th[20];
    n = v2g_net_tcp_build(th, 0xC001, 15118, 0x11223344u, 0x55667788u, 0x18, 0xa02d);
    CHECK(n == 20, "tcp header len 20");
    CHECK(th[4] == 0x11 && th[7] == 0x44, "tcp seq BE");
    CHECK(th[8] == 0x55 && th[11] == 0x88, "tcp ack BE");
    CHECK((th[12] >> 4) == 5, "tcp data offset = 5 words");
    CHECK(th[13] == 0x18, "tcp flags ACK|PSH");
    CHECK(th[14] == 0xa0 && th[15] == 0x2d, "tcp window BE");

    /* --- Internet checksum (0x08098CAC): classic vector {00 01 f2 03 f4 f5 f6 f7} -> 0x220d --- */
    uint8_t ck[8] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    CHECK(v2g_net_inet_chksum(ck, 8) == 0x220d, "inet checksum classic vector 0x220d");
    CHECK(v2g_net_inet_chksum(ck, 0) == 0xFFFF, "inet checksum empty -> 0xFFFF");
    /* odd length: trailing byte padded high */
    uint8_t ck3[3] = {0x00, 0x01, 0xf2};
    CHECK(v2g_net_inet_chksum(ck3, 3) == (uint16_t)~(0x0001 + 0xf200), "inet checksum odd byte");

    /* --- Ethernet header + EtherType demux (0x0809D914) --- */
    uint8_t eth[14];
    uint8_t dmac[6] = {0x33, 0x33, 0, 0, 0, 1}, smac[6] = {0xFE, 0xFF, 0xFE, 0xFF, 0, 1};
    n = v2g_net_eth_build(eth, dmac, smac, V2G_ETHTYPE_IPV6);
    CHECK(n == 14, "eth header len 14");
    CHECK(eth[12] == 0x86 && eth[13] == 0xDD, "ethertype IPv6 BE 86 DD");
    CHECK(v2g_net_ethertype(eth, 14) == 0x86DD, "ethertype demux IPv6 (normalized wire)");
    eth[12] = 0x88; eth[13] = 0xE1;
    CHECK(v2g_net_ethertype(eth, 14) == 0x88E1, "ethertype demux MME");
    CHECK(v2g_net_ethertype(eth, 13) == 0, "ethertype rejects len < 14");

    /* --- TLS decision (CORRECTED; state4 0x080207BC): TLS iff byte == 0 --- */
    CHECK(v2g_net_tls_decision(0x00) == 1, "TLS decision: security 0x00 -> TLS");
    CHECK(v2g_net_tls_decision(0x10) == 0, "TLS decision: security 0x10 -> plain (No-TLS)");
    CHECK(v2g_net_tls_decision(0x30) == 0, "TLS decision: nonzero -> plain");

    /* --- local MAC setter -> brings up the stack + EUI-64 link-local (0x08090D68) --- */
    v2g_net_init();
    stub_init_calls = 0;
    v2g_net_set_local_mac(mac);
    CHECK(stub_init_calls == 1, "set_local_mac brings up v2g_stack_init (lwIP netif)");
    CHECK(stub_connected_fn != NULL && stub_recv_fn != NULL && stub_closed_fn != NULL,
          "set_local_mac wires the TCP connected/recv/closed callbacks");
    uint8_t ll[16]; v2g_net_ipv6_linklocal(mac, ll);
    CHECK(memcmp(v2g_net_get()->local_ip, ll, 16) == 0, "set_local_mac -> EUI-64 link-local IPv6");

    /* --- V2GTP deframe: single, multi, partial, resync --- */
    v2g_deframe_t df;
    v2g_deframe_init(&df);
    uint8_t f1[16], f2[12];
    uint16_t l1 = mk_exi(f1, 8);    /* 16 bytes */
    uint16_t l2 = mk_exi(f2, 4);    /* 12 bytes */
    static uint8_t got[8][256]; static uint16_t got_len[8]; static int got_n;
    got_n = 0;
    void cb(const uint8_t *fr, uint16_t ln, void *arg) {
        (void)arg; memcpy(got[got_n], fr, ln); got_len[got_n] = ln; got_n++;
    }
    CHECK(v2g_deframe_push(&df, f1, l1, cb, 0) == 1, "deframe single frame");
    CHECK(got_n == 1 && got_len[0] == l1, "deframe single frame len");
    /* two frames in one push */
    got_n = 0; v2g_deframe_init(&df);
    uint8_t two[28]; memcpy(two, f1, l1); memcpy(two + l1, f2, l2);
    CHECK(v2g_deframe_push(&df, two, (uint16_t)(l1 + l2), cb, 0) == 2, "deframe two frames");
    CHECK(got_n == 2 && got_len[0] == l1 && got_len[1] == l2, "deframe two frames lens");
    /* partial frame across pushes */
    got_n = 0; v2g_deframe_init(&df);
    CHECK(v2g_deframe_push(&df, f1, 5, cb, 0) == 0, "deframe partial (5 bytes) -> 0 frames");
    CHECK(v2g_deframe_push(&df, f1 + 5, (uint16_t)(l1 - 5), cb, 0) == 1, "deframe completes partial");
    CHECK(got_n == 1 && got_len[0] == l1 && memcmp(got[0], f1, l1) == 0, "deframe partial reassembled");
    /* byte-by-byte push */
    got_n = 0; v2g_deframe_init(&df);
    uint16_t total = 0;
    for (uint16_t i = 0; i < l1; i++) total += v2g_deframe_push(&df, f1 + i, 1, cb, 0);
    CHECK(total == 1 && got_n == 1, "deframe byte-by-byte");

    /* --- transport SM: plain path --- */
    v2g_net_init();
    const v2g_net_t *nt = v2g_net_get();
    CHECK(nt->state == V2G_NET_IDLE, "net init idle");
    CHECK(nt->ciphers[0] == 0xC023 && nt->ciphers[1] == 0xC025, "net cipher list {0xC023,0xC025}");
    CHECK(nt->authmode == 2, "net authmode VERIFY_REQUIRED");
    uint8_t secc[16]; memset(secc, 0, 16); secc[0] = 0xFE; secc[1] = 0x80; secc[15] = 0x02;
    stub_connect_calls = 0;
    v2g_net_start_tcp(secc, 15118, 0x10, 1000);   /* security 0x10 -> plain */
    CHECK(nt->state == V2G_NET_TCP_CONNECT, "start_tcp -> TCP_CONNECT");
    CHECK(nt->use_tls == 0 && nt->mode == V2G_NET_MODE_PLAIN, "plain: use_tls 0 mode1");
    CHECK(nt->secc_port == 15118, "start_tcp secc port");
    CHECK(stub_connect_calls == 1 && stub_connect_port == 15118 &&
          memcmp(stub_connect_ip, secc, 16) == 0, "start_tcp -> v2g_stack_tcp_connect(secc,port)");
    v2g_net_tcp_connected(1100);
    CHECK(nt->state == V2G_NET_ESTABLISHED, "plain connected -> ESTABLISHED");
    CHECK(nt->tcp_connected == 1, "tcp connected flag");
    CHECK(stub_tls_setup_calls == 0, "plain mode does NOT set up TLS");
    /* idle close at 300 polls */
    for (int i = 0; i < 299; i++) v2g_net_step(2000 + (uint32_t)i * 10);
    CHECK(nt->state == V2G_NET_ESTABLISHED, "idle 299 polls still established");
    CHECK(stub_poll_calls >= 299, "step drives v2g_stack_poll (lwIP timeouts)");
    v2g_net_step(2000 + 299 * 10);
    CHECK(nt->state == V2G_NET_CLOSED, "idle 300 polls -> CLOSED");
    CHECK(stub_tcp_close_calls >= 1, "idle close -> v2g_stack_tcp_close");

    /* --- transport SM: TLS path --- */
    v2g_net_init();
    stub_tls_setup_calls = 0; stub_tls_handshake_calls = 0; stub_tls_handshake_ret = 1;
    v2g_net_start_tcp(secc, 15118, 0x00, 1000);   /* security 0x00 -> TLS */
    CHECK(nt->use_tls == 1 && nt->mode == V2G_NET_MODE_TLS, "TLS: use_tls 1 mode2");
    v2g_net_tcp_connected(1100);
    CHECK(nt->state == V2G_NET_TLS_HANDSHAKE, "TLS connected -> TLS_HANDSHAKE");
    CHECK(nt->tls_done == 0, "TLS handshake pending");
    CHECK(stub_tls_setup_calls == 1, "TLS connected -> v2g_stack_tls_setup (mbedTLS config + CA)");
    CHECK(stub_tls_handshake_calls >= 1, "TLS connected drives v2g_stack_tls_handshake");
    v2g_net_step(1200);
    CHECK(nt->state == V2G_NET_TLS_HANDSHAKE, "TLS handshake WANT_READ stays in handshake");
    /* handshake completes -> ESTABLISHED */
    stub_tls_handshake_ret = 0;
    v2g_net_step(1300);
    CHECK(nt->state == V2G_NET_ESTABLISHED && nt->tls_done == 1, "TLS handshake done -> ESTABLISHED");
    /* connect timeout (plain) */
    v2g_net_init();
    v2g_net_start_tcp(secc, 15118, 0x10, 0);
    v2g_net_step(30001);
    CHECK(nt->state == V2G_NET_CLOSED, "TCP connect timeout 30000 -> CLOSED");

    /* --- EXI dispatch -> ccs2_rx_exi spy --- */
    v2g_net_init();
    spy_exi_calls = 0;
    uint8_t exi[16]; uint16_t el = mk_exi(exi, 8);
    int r = v2g_net_exi_dispatch(exi, el, 5000);
    CHECK(r == 0, "exi dispatch returns EXI_OK");
    CHECK(spy_exi_calls == 1, "exi dispatch calls ccs2_rx_exi");
    CHECK(spy_exi_len == el && spy_exi_ms == 5000, "exi dispatch frame len + ms");
    CHECK(memcmp(spy_exi, exi, el) == 0, "exi dispatch frame bytes");
    CHECK(nt->rx_frames == 1, "exi dispatch rx_frames count");
    /* non-EXI type (SDP res 0x9001) -> not dispatched */
    uint8_t sdpf[28]; memset(sdpf, 0, 28); v2gtp_encode(sdpf, 20, V2GTP_TYPE_SDP_RES);
    spy_exi_calls = 0;
    r = v2g_net_exi_dispatch(sdpf, 28, 5000);
    CHECK(r == 0 && spy_exi_calls == 0, "non-EXI type not dispatched to ccs2_rx_exi");

    /* --- RX ethernet entry forwards to the live stack (lwIP demux is library-validated) --- */
    v2g_net_init();
    uint8_t rxbuf[64]; memset(rxbuf, 0, sizeof rxbuf);
    v2g_net_rx_ethernet(rxbuf, 14, 7000);   /* thin forward -> v2g_stack_rx_ethernet */
    CHECK(nt->state == V2G_NET_IDLE, "rx_ethernet forwards to stack without altering SM");

    /* --- send router: udp_send -> v2g_stack_udp_send (SDP multicast) --- */
    v2g_net_init();
    stub_udp_send_calls = 0;
    uint8_t sdpreq[10]; memset(sdpreq, 0, 10);
    sdpreq[8] = 0x10; sdpreq[9] = 0;   /* {security, transport=0} */
    v2gtp_encode(sdpreq, 2, V2GTP_TYPE_SDP_REQ);
    int sn = v2g_net_udp_send(sdpreq, 10);
    CHECK(sn == 10, "udp_send returns payload len");
    CHECK(stub_udp_send_calls == 1, "udp_send -> v2g_stack_udp_send");
    CHECK(nt->tx_frames == 1, "udp_send tx_frames count");

    /* --- send router: tcp_send plain established -> v2g_stack_tcp_send --- */
    v2g_net_init();
    stub_tcp_send_calls = 0;
    v2g_net_start_tcp(secc, 15118, 0x10, 0);
    v2g_net_tcp_connected(100);
    int tn = v2g_net_tcp_send(exi, el, 200);
    CHECK(tn == (int)el, "tcp_send plain returns frame len");
    CHECK(stub_tcp_send_calls == 1 && stub_tcp_send_len == el, "tcp_send plain -> v2g_stack_tcp_send");
    /* tcp_send before established -> error */
    v2g_net_init();
    CHECK(v2g_net_tcp_send(exi, el, 200) == -1, "tcp_send before established -> -1");

    /* --- send router: tcp_send TLS established -> v2g_stack_tls_write (ssl_write) --- */
    v2g_net_init();
    stub_tls_write_calls = 0; stub_tcp_send_calls = 0; stub_tls_handshake_ret = 0;
    v2g_net_start_tcp(secc, 15118, 0x00, 0);
    v2g_net_tcp_connected(100);   /* TLS setup + handshake(done) -> ESTABLISHED */
    CHECK(nt->state == V2G_NET_ESTABLISHED, "TLS established for send-router test");
    tn = v2g_net_tcp_send(exi, el, 200);
    CHECK(tn == (int)el, "tcp_send TLS returns frame len");
    CHECK(stub_tls_write_calls == 1, "tcp_send TLS -> v2g_stack_tls_write (mbedTLS ssl_write)");
    CHECK(stub_tcp_send_calls == 0, "tcp_send TLS does NOT use plain tcp_send");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}