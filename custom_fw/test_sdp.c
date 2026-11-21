/* test_sdp.c — host unit test for SDP + V2GTP + appHandshake (custom_fw/src/sdp.c, REPORT §5.9).
 * Build + run:
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_sdp \
 *       test_sdp.c src/sdp.c src/v2gtp.c && ./test_sdp'
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sdp.h"
#include "v2gtp.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

/* build a valid 28-byte SDP response with the given security/port */
static void mk_res(uint8_t *b, uint8_t security, uint16_t port)
{
    memset(b, 0, 28);
    b[8] = 0xfe; b[9] = 0x80; b[23] = 0x01;   /* a nonzero IPv6 address (fe80::1) */
    b[0x18] = port >> 8; b[0x19] = port & 0xFF;
    b[0x1a] = security; b[0x1b] = 0;          /* transport TCP */
    v2gtp_encode(b, 20, V2GTP_TYPE_SDP_RES);
}

int main(void)
{
    /* --- security select (0x080204FA): (count & 0xFF)==0 -> 0x10 else 0x00, LOW-BYTE-ONLY --- */
    CHECK(sdp_security_select(0) == SDP_SECURITY_TLS,    "count 0 -> TLS 0x10");
    CHECK(sdp_security_select(1) == SDP_SECURITY_NONE,   "count 1 -> no-TLS 0x00");
    CHECK(sdp_security_select(5) == SDP_SECURITY_NONE,   "count 5 -> no-TLS");
    CHECK(sdp_security_select(0x100) == SDP_SECURITY_TLS,"count 0x100 -> TLS (low byte 0)");
    CHECK(sdp_security_select(0x101) == SDP_SECURITY_NONE,"count 0x101 -> no-TLS (low byte 1)");

    /* --- SDP request build: 01 FE 90 00 00 00 00 02 <SEC> 00 --- */
    uint8_t req[16];
    uint16_t n = sdp_build_req(req, SDP_SECURITY_TLS);
    CHECK(n == 10, "SDP req len 10");
    CHECK(req[0] == 0x01 && req[1] == 0xFE && req[2] == 0x90 && req[3] == 0x00, "V2GTP 0x9000");
    CHECK(req[7] == 2, "payload len 2");
    CHECK(req[8] == SDP_SECURITY_TLS && req[9] == 0, "payload {security, transport=0}");

    /* --- SDP response validator (0x080212E0) --- */
    uint8_t res[28];
    mk_res(res, SDP_SECURITY_NONE, 15118);
    CHECK(sdp_res_valid(res, 28) == 1, "valid no-TLS res");
    mk_res(res, SDP_SECURITY_TLS, 15118);
    CHECK(sdp_res_valid(res, 28) == 1, "valid TLS res");
    /* wrong length */
    CHECK(sdp_res_valid(res, 27) == 0, "reject len != 28");
    /* wrong transport */
    mk_res(res, 0, 15118); res[0x1b] = 1;
    CHECK(sdp_res_valid(res, 28) == 0, "reject transport != 0");
    /* invalid security 0x30 */
    mk_res(res, 0x30, 15118);
    CHECK(sdp_res_valid(res, 28) == 0, "reject security 0x30");
    /* zero port */
    mk_res(res, 0, 0);
    CHECK(sdp_res_valid(res, 28) == 0, "reject port 0");
    /* zero IP */
    mk_res(res, 0, 15118); memset(res + 8, 0, 16);
    CHECK(sdp_res_valid(res, 28) == 0, "reject all-zero IP");
    /* wrong V2GTP type */
    mk_res(res, 0, 15118); res[2] = 0x90; res[3] = 0x00;   /* 0x9000 req, not res */
    CHECK(sdp_res_valid(res, 28) == 0, "reject type 0x9000");

    /* --- SDP response parse --- */
    mk_res(res, SDP_SECURITY_TLS, 0x3B0E);
    uint8_t ip[16]; uint16_t port; uint8_t sec;
    sdp_res_parse(res, ip, &port, &sec);
    CHECK(port == 15118, "parse port BE -> 15118");
    CHECK(sec == SDP_SECURITY_TLS, "parse security 0x10");
    CHECK(ip[0] == 0xfe && ip[15] == 0x01, "parse IPv6 bytes");

    /* --- appHandshake protocol selection (SchemaID 1->DIN, 2->ISO) --- */
    CHECK(sdp_select_protocol(1) == SDP_PROTO_DIN, "SchemaID 1 -> DIN");
    CHECK(sdp_select_protocol(2) == SDP_PROTO_ISO, "SchemaID 2 -> ISO");
    CHECK(sdp_select_protocol(0) == 0, "SchemaID 0 -> shutdown");
    CHECK(sdp_select_protocol(3) == 0, "SchemaID 3 -> shutdown");

    /* --- SM: init -> request -> injected response -> TCP_CONNECT, TLS decision --- */
    sdp_init(0);   /* count 0 -> TLS req */
    const sdp_t *s = sdp_get();
    CHECK(s->req_security == SDP_SECURITY_TLS, "init req security TLS");
    CHECK(s->retries == SDP_RETRY_COUNT, "init retries 50");
    sdp_step(0);   /* IDLE -> REQ -> send -> WAIT_RES */
    CHECK(s->state == SDP_ST_WAIT_RES, "step -> WAIT_RES");
    CHECK(s->timer_ms == SDP_T_SUBSEQ_MS, "timer 250 after first send");
    mk_res(res, SDP_SECURITY_TLS, 15118);
    sdp_rx(res, 28);
    CHECK(s->state == SDP_ST_TCP_CONNECT, "valid res -> TCP_CONNECT");
    CHECK(s->secc_port == 15118 && s->use_tls == 1, "SECC port + TLS iff security!=0");
    /* no-TLS response -> use_tls 0 */
    sdp_init(1);
    sdp_step(0);
    mk_res(res, SDP_SECURITY_NONE, 15118);
    sdp_rx(res, 28);
    CHECK(s->use_tls == 0, "no-TLS res -> use_tls 0");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}