/* test_v2gtp.c — host unit test for V2GTP framing (custom_fw/src/v2gtp.c, REPORT §5.9).
 * Build + run:
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_v2gtp \
 *       test_v2gtp.c src/v2gtp.c && ./test_v2gtp'
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "v2gtp.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

int main(void)
{
    uint8_t buf[64];

    /* encode EXI type 0x8001, payload len 4 -> wire 01 FE 80 01 00 00 00 04 */
    memset(buf, 0, sizeof buf);
    buf[8] = 0xAA; buf[9] = 0xBB; buf[10] = 0xCC; buf[11] = 0xDD;
    uint16_t n = v2gtp_encode(buf, 4, V2GTP_TYPE_EXI);
    CHECK(n == 12, "encode total len = payload+8");
    CHECK(buf[0] == 0x01 && buf[1] == 0xFE, "ver/inv 01 FE");
    CHECK(buf[2] == 0x80 && buf[3] == 0x01, "type BE 80 01");
    CHECK(buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] == 4, "len BE 00000004");
    CHECK(buf[8] == 0xAA && buf[11] == 0xDD, "payload preserved");

    /* encode SDP req 0x9000 len 2 -> 01 FE 90 00 00 00 00 02 */
    n = v2gtp_encode(buf, 2, V2GTP_TYPE_SDP_REQ);
    CHECK(n == 10 && buf[2] == 0x90 && buf[3] == 0x00 && buf[7] == 2, "SDP req header");

    /* parse valid EXI frame */
    uint16_t plen = 0;
    uint16_t t = v2gtp_parse(buf, 12, &plen);   /* buf still SDP req len2; re-encode EXI */
    v2gtp_encode(buf, 4, V2GTP_TYPE_EXI);
    t = v2gtp_parse(buf, 12, &plen);
    CHECK(t == V2GTP_TYPE_EXI, "parse returns wire type 0x8001");
    CHECK(plen == 4, "parse payload len 4");

    /* parse SDP response 0x9001 */
    v2gtp_encode(buf, 20, V2GTP_TYPE_SDP_RES);
    t = v2gtp_parse(buf, 28, &plen);
    CHECK(t == V2GTP_TYPE_SDP_RES && plen == 20, "parse SDP res 0x9001 len20");

    /* reject: bad version */
    v2gtp_encode(buf, 4, V2GTP_TYPE_EXI);
    buf[0] = 0x02;
    CHECK(v2gtp_parse(buf, 12, &plen) == 0, "reject bad version");
    /* reject: bad inverse */
    v2gtp_encode(buf, 4, V2GTP_TYPE_EXI);
    buf[1] = 0xFF;
    CHECK(v2gtp_parse(buf, 12, &plen) == 0, "reject bad inverse");
    /* reject: short buffer (< payload+8) */
    v2gtp_encode(buf, 4, V2GTP_TYPE_EXI);
    CHECK(v2gtp_parse(buf, 11, &plen) == 0, "reject len < payload+8");
    /* reject: header-only short */
    CHECK(v2gtp_parse(buf, 7, &plen) == 0, "reject len < 8");
    /* accept: buffer larger than payload+8 */
    v2gtp_encode(buf, 4, V2GTP_TYPE_EXI);
    CHECK(v2gtp_parse(buf, 64, &plen) == V2GTP_TYPE_EXI, "accept len > payload+8");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}