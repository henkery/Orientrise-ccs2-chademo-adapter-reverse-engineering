/* test_qca7005.c — host unit test for the QCA7005 transport PURE helpers (no hardware).
 * Verifies the MAC-read REQ build, the MAC-read CNF validation, and the RX packet-header parse
 * math against the byte-derived stock behavior (A_qca7005_transport.md). The SPI hardware
 * primitives are disasm-verified separately (build + verify_qca.py).
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_qca7005 test_qca7005.c src/qca7005.c && ./test_qca7005'
 * qca7005.c references tick_delay_ms only in hardware paths (not exercised here); a stub is
 * provided so the pure helpers link on the host.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "qca7005.h"

/* host stub: the pure helpers never call the delay (hardware paths only). */
void tick_delay_ms(uint32_t ms) { (void)ms; }

static int checks = 0, failures = 0;
#define CK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL line %d: %s\n", __LINE__, #cond); } } while (0)

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
/* build a valid RX packet header for total-length field L (fp = L-10, sl = L+4). */
static void mk_hdr(uint8_t *h, uint32_t L)
{
    memset(h, 0, 12);
    put_be32(h, L);
    put_be32(h + 4, QCA_PKT_MAGIC);
    put_be16(h + 8, (uint16_t)(L - 10));
}

static void test_build_mac_req(void)
{
    uint8_t f[24];
    memset(f, 0xEE, sizeof(f));
    uint16_t n = qca7005_build_mac_req(f);
    CK(n == 24);
    /* dest PIB MAC 00:B0:52:00:00:01 */
    CK(f[0] == 0x00 && f[1] == 0xB0 && f[2] == 0x52 && f[3] == 0x00 && f[4] == 0x00 && f[5] == 0x01);
    /* src host MAC FE:FF:FE:FF:00:01 */
    CK(f[6] == 0xFE && f[7] == 0xFF && f[8] == 0xFE && f[9] == 0xFF && f[10] == 0x00 && f[11] == 0x01);
    CK(f[12] == 0x88 && f[13] == 0xE1);          /* EtherType 0x88E1 on-wire */
    CK(f[14] == 0x00);                            /* MMV 0 */
    CK(f[15] == 0x00 && f[16] == 0xA0);           /* MMTYPE 0xA000 LE */
    CK(f[17] == 0x00 && f[18] == 0xB0);           /* param 0xB000 LE */
    CK(f[19] == 0x52);                            /* op 'R' */
    CK(f[20] == 0 && f[21] == 0 && f[22] == 0 && f[23] == 0);  /* 4 zero bytes */
}

/* a valid MAC-read CNF addressed back to the host. */
static void mk_cnf(uint8_t *f)
{
    memset(f, 0, 24);
    /* dest = host MAC */
    f[0] = 0xFE; f[1] = 0xFF; f[2] = 0xFE; f[3] = 0xFF; f[4] = 0x00; f[5] = 0x01;
    /* src = PIB MAC (the read result) */
    f[6] = 0x00; f[7] = 0xB0; f[8] = 0x52; f[9] = 0x12; f[10] = 0x34; f[11] = 0x56;
    f[12] = 0x88; f[13] = 0xE1;
    f[14] = 0x00;
    f[15] = 0x01; f[16] = 0xA0;                   /* MMTYPE 0xA001 CNF */
    f[0x14] = 0x00;                               /* status 0 = success */
}

static void test_mac_cnf_valid(void)
{
    uint8_t f[24];
    mk_cnf(f);
    CK(qca7005_mac_cnf_valid(f, 24) == 1);
    CK(qca7005_mac_cnf_valid(f, 23) == 0);        /* too short */

    mk_cnf(f); f[12] = 0x08;                       /* wrong EtherType */
    CK(qca7005_mac_cnf_valid(f, 24) == 0);
    mk_cnf(f); f[13] = 0xE2;
    CK(qca7005_mac_cnf_valid(f, 24) == 0);

    mk_cnf(f); f[0] = 0x00;                        /* wrong dest (not host) */
    CK(qca7005_mac_cnf_valid(f, 24) == 0);

    mk_cnf(f); f[15] = 0x00;                       /* MMTYPE 0xA000 REQ not CNF */
    CK(qca7005_mac_cnf_valid(f, 24) == 0);
    mk_cnf(f); f[16] = 0x60;                       /* wrong MMTYPE high */
    CK(qca7005_mac_cnf_valid(f, 24) == 0);

    mk_cnf(f); f[0x14] = 0x01;                     /* nonzero status = failure */
    CK(qca7005_mac_cnf_valid(f, 24) == 0);
}

static void test_pkt_check(void)
{
    uint8_t h[12];
    uint16_t fl, pl;

    mk_hdr(h, 74);                                 /* L=74, fp=64, sl=78 */
    CK(qca7005_pkt_check(h, &fl, &pl) == 1);
    CK(fl == 64 && pl == 78);

    mk_hdr(h, 0x18 + 1508);                        /* max L-0x18 = 1508 */
    CK(qca7005_pkt_check(h, &fl, &pl) == 1);
    CK(fl == (uint16_t)(0x18 + 1508 - 10) && pl == (uint16_t)(0x18 + 1508 + 4));

    mk_hdr(h, 74); put_be32(h + 4, 0xAAAAAAAC);    /* bad magic */
    CK(qca7005_pkt_check(h, &fl, &pl) == 0);

    mk_hdr(h, 74); put_be16(h + 8, 63);            /* fp != L-10 */
    CK(qca7005_pkt_check(h, &fl, &pl) == 0);

    mk_hdr(h, 0x17);                               /* L < 0x18 */
    CK(qca7005_pkt_check(h, &fl, &pl) == 0);

    mk_hdr(h, 0x18 + 1509);                        /* L-0x18 > 1508 */
    CK(qca7005_pkt_check(h, &fl, &pl) == 0);

    /* fp+14 != L+4: craft L=74 but fp=64 is correct; force inconsistency via fp=65 */
    mk_hdr(h, 74); put_be16(h + 8, 65);            /* fp=65 -> fp+14=79 != sl=78, also != L-10 */
    CK(qca7005_pkt_check(h, &fl, &pl) == 0);
}

int main(void)
{
    test_build_mac_req();
    test_mac_cnf_valid();
    test_pkt_check();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
