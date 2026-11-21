/* test_exi.c — host unit test for the EXI bit-level codec primitives (REPORT §5.9, Agent E).
 * Validates byte-exact MSB-first read/write, varlen unsigned, signed ones-complement, octet,
 * PhysicalValueType wire order (Multiplier,Unit,Value), and V2GTP framing against known vectors
 * + round-trips. Pure logic (gcc). Build: gcc -Isrc test_exi.c src/exi.c -o test_exi && ./test_exi
 */
#include <stdio.h>
#include <string.h>
#include "exi.h"

static int checks = 0, failures = 0;
#define CK(c, m) do { checks++; if (!(c)) { failures++; printf("FAIL: %s\n", m); } \
                      else printf("ok: %s\n", m); } while (0)

static void test_bits_read(void)
{
    /* 0xAB = 10101011 : top3=101=5, next5=01011=0x0B */
    uint8_t buf[1] = { 0xAB };
    exi_stream_t s; exi_decode_init(&s, buf, 1);
    uint32_t v;
    CK(exi_read_bits(&s, 3, &v) == 0 && v == 5, "readBits(3) of 0xAB = 5 (MSB-first)");
    CK(exi_read_bits(&s, 5, &v) == 0 && v == 0x0B, "readBits(5) remainder = 0x0B");
    CK(exi_read_bits(&s, 1, &v) == EXI_ERR_EOF, "readBits past capacity -> EOF");

    /* cross-byte: 0xFF 0x00 read 12 -> 0xFF0 */
    uint8_t b2[2] = { 0xFF, 0x00 };
    exi_decode_init(&s, b2, 2);
    CK(exi_read_bits(&s, 12, &v) == 0 && v == 0xFF0, "readBits(12) across bytes = 0xFF0");

    /* n=0 -> 0, no consumption */
    exi_decode_init(&s, buf, 1);
    CK(exi_read_bits(&s, 0, &v) == 0 && v == 0 && s.pos == 0, "readBits(0) = 0 no consume");
}

static void test_bits_write(void)
{
    /* write 3 bits 5 (101) then 5 bits 0x15 (10101) -> 10110101 = 0xB5 */
    uint8_t buf[4]; exi_stream_t s; exi_encode_init(&s, buf, 4, 0);
    CK(exi_write_bits(&s, 3, 5) == 0, "writeBits(3,5) ok");
    CK(exi_write_bits(&s, 5, 0x15) == 0, "writeBits(5,0x15) ok");
    CK(s.pos == 1 && buf[0] == 0xB5, "writeBits 3+5 flush byte = 0xB5 (MSB-first)");

    /* partial trailing byte: write 3 bits 5 -> curbyte 0xA0, finish pads low bits */
    exi_encode_init(&s, buf, 4, 0);
    exi_write_bits(&s, 3, 5);
    uint32_t n = exi_encode_finish(&s);
    CK(n == 1 && buf[0] == 0xA0, "writeBits(3,5)+finish = 0xA0 (left-aligned, 0 pad)");

    /* round-trip arbitrary widths */
    uint8_t rt[8]; exi_encode_init(&s, rt, 8, 0);
    exi_write_bits(&s, 7, 0x55); exi_write_bits(&s, 9, 0x1AA); exi_write_bits(&s, 4, 0x9);
    uint32_t len = exi_encode_finish(&s);
    exi_stream_t d; exi_decode_init(&d, rt, len);
    uint32_t a, b, c;
    exi_read_bits(&d, 7, &a); exi_read_bits(&d, 9, &b); exi_read_bits(&d, 4, &c);
    CK(a == 0x55 && b == 0x1AA && c == 0x9, "bit round-trip 7/9/4 widths");

    /* capacity overflow -> EOF (stock checks capacity only on flush, bitsleft==0). Fill buf[0]
     * (pos=1=cap), then write a full byte to force a flush past capacity. A partial bit write
     * buffers in curbyte without flushing and returns OK until the byte fills. */
    uint8_t small[1]; exi_encode_init(&s, small, 1, 0);
    exi_write_bits(&s, 8, 0xFF);
    CK(exi_write_bits(&s, 1, 1) == EXI_OK, "writeBits partial bit buffers (no flush) -> OK");
    CK(exi_write_bits(&s, 7, 0x55) == EXI_ERR_EOF, "writeBits flush past capacity -> EOF");
}

static void test_varlen(void)
{
    uint8_t buf[8]; exi_stream_t s;
    /* known EXI unsignedShort varlen vectors (7-bit groups LSB-first, bit7 continuation) */
    struct { uint16_t v; uint8_t enc[3]; int n; } vec[] = {
        { 0,     { 0x00, 0, 0 }, 1 },
        { 127,   { 0x7F, 0, 0 }, 1 },
        { 128,   { 0x80, 0x01, 0 }, 2 },
        { 16383, { 0xFF, 0x7F, 0 }, 2 },
        { 16384, { 0x80, 0x80, 0x01 }, 3 },
        { 65535, { 0xFF, 0xFF, 0x03 }, 3 },
    };
    for (unsigned i = 0; i < sizeof vec / sizeof vec[0]; i++) {
        exi_encode_init(&s, buf, 8, 0);
        exi_write_u16(&s, vec[i].v);
        uint32_t n = exi_encode_finish(&s);
        char m[64]; snprintf(m, sizeof m, "u16 varlen %u encode len %d", vec[i].v, vec[i].n);
        CK(n == (uint32_t)vec[i].n && memcmp(buf, vec[i].enc, vec[i].n) == 0, m);
        exi_stream_t d; exi_decode_init(&d, buf, n);
        uint16_t out; exi_read_u16(&d, &out);
        snprintf(m, sizeof m, "u16 varlen %u round-trip", vec[i].v);
        CK(out == vec[i].v, m);
    }
    /* u32 vector: 0xFFFFFFFF -> 5 groups */
    exi_encode_init(&s, buf, 8, 0);
    exi_write_u32(&s, 0xFFFFFFFFu);
    uint32_t n = exi_encode_finish(&s);
    exi_stream_t d; exi_decode_init(&d, buf, n);
    uint32_t out; exi_read_u32(&d, &out);
    CK(n == 5 && out == 0xFFFFFFFFu, "u32 varlen 0xFFFFFFFF round-trip (5 groups)");
}

static void test_signed(void)
{
    uint8_t buf[8]; exi_stream_t s;
    /* sign-bit + ones-complement magnitude: 0->sign0 mag0; 5->sign0 mag5; -1->sign1 mag0;
     * -5->sign1 mag4 (~4 = 0xFFFB = -5). */
    struct { int16_t v; uint8_t sign; uint16_t mag; } vec[] = {
        { 0, 0, 0 }, { 5, 0, 5 }, { -1, 1, 0 }, { -5, 1, 4 }, { 32767, 0, 32767 },
    };
    for (unsigned i = 0; i < sizeof vec / sizeof vec[0]; i++) {
        exi_encode_init(&s, buf, 8, 0);
        exi_write_signed(&s, vec[i].v);
        uint32_t n = exi_encode_finish(&s);
        exi_stream_t d; exi_decode_init(&d, buf, n);
        uint8_t sign; exi_read_bool(&d, &sign);
        uint16_t mag; exi_read_u16(&d, &mag);
        char m[64]; snprintf(m, sizeof m, "signed %d sign/mag", vec[i].v);
        CK(sign == vec[i].sign && mag == vec[i].mag, m);
        exi_decode_init(&d, buf, n);
        int16_t out; exi_read_signed(&d, &out);
        snprintf(m, sizeof m, "signed %d round-trip", vec[i].v);
        CK(out == vec[i].v, m);
    }
}

static void test_pvt(void)
{
    uint8_t buf[16]; exi_stream_t s;
    /* PVT wire order Multiplier(3-bit=mult+3), Unit(2-bit choice + 4-bit), Value(signed).
     * mult=-1 (wire 2), unit=5 present, value=4000. */
    exi_pvt_t p = { .mult = -1, .unit = 5, .unit_present = 1, .value = 4000 };
    exi_encode_init(&s, buf, 16, 0);
    CK(exi_write_pvt(&s, &p) == 0, "write_pvt ok");
    uint32_t n = exi_encode_finish(&s);
    /* first 3 bits = mult+3 = 2 (010); next 2 bits choice = 0 (00); next 4 bits unit = 5 (0101)
     * -> first byte 01000010 = 0x42, then 1 bit value-sign 0 ... */
    CK(buf[0] == 0x42, "PVT wire byte0 = 0x42 (mult=2,choice=0,unit=5 top bit)");
    exi_stream_t d; exi_decode_init(&d, buf, n);
    exi_pvt_t out;
    CK(exi_read_pvt(&d, &out) == 0, "read_pvt ok");
    CK(out.mult == -1 && out.unit == 5 && out.unit_present == 1 && out.value == 4000,
       "PVT round-trip mult=-1 unit=5 value=4000");

    /* unit absent: choice=1 */
    exi_pvt_t q = { .mult = 0, .unit = 0, .unit_present = 0, .value = 230 };
    exi_encode_init(&s, buf, 16, 0);
    exi_write_pvt(&s, &q);
    n = exi_encode_finish(&s);
    exi_decode_init(&d, buf, n);
    exi_read_pvt(&d, &out);
    CK(out.mult == 0 && out.unit_present == 0 && out.value == 230, "PVT unit-absent round-trip");

    /* multiplier range -3..3 -> wire 0..6 */
    for (int mult = -3; mult <= 3; mult++) {
        exi_pvt_t r = { .mult = (int8_t)mult, .unit = 1, .unit_present = 1, .value = 100 };
        exi_encode_init(&s, buf, 16, 0);
        exi_write_pvt(&s, &r);
        n = exi_encode_finish(&s);
        exi_decode_init(&d, buf, n);
        exi_read_pvt(&d, &out);
        char m[48]; snprintf(m, sizeof m, "PVT mult %d wire round-trip", mult);
        CK(out.mult == mult && out.value == 100, m);
    }
}

static void test_octet(void)
{
    uint8_t buf[16]; exi_stream_t s;
    uint8_t data[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    exi_encode_init(&s, buf, 16, 0);
    exi_write_octet(&s, data, 4);
    uint32_t n = exi_encode_finish(&s);
    exi_stream_t d; exi_decode_init(&d, buf, n);
    uint8_t out[8]; uint16_t len;
    CK(exi_read_octet(&d, out, 8, &len) == 0 && len == 4 && memcmp(out, data, 4) == 0,
       "octet string round-trip DEADBEEF");
}

static void test_framing(void)
{
    uint8_t buf[32]; exi_stream_t s;
    /* encode: reserve 8-byte V2GTP, leading 0x80, 7-bit event 0x12 (CurrentDemandRes) */
    exi_encode_init(&s, buf, 32, EXI_V2GTP_HDR_LEN);
    CK(exi_encode_header(&s, EXI_EV_CURRENTDEMAND_RES) == 0, "encode_header ok");
    CK(buf[8] == 0x80, "framing leading byte buf[8] = 0x80");
    uint32_t n = exi_encode_finish(&s);
    /* event 0x12 = 0010010 (7 bits) left-aligned into the byte after the 0x80 -> 0x12<<1 = 0x24.
     * (0x24 is rejected only as a LEADING byte; here it is the event byte after 0x80, which is ok.) */
    CK(buf[9] == (uint8_t)(EXI_EV_CURRENTDEMAND_RES << 1), "framing event byte = ev<<1");
    /* decode: strip 8-byte header (pass body from buf+8) */
    exi_stream_t d; exi_decode_init(&d, buf + EXI_V2GTP_HDR_LEN, n - EXI_V2GTP_HDR_LEN);
    uint8_t ev;
    CK(exi_decode_header(&d, &ev) == 0 && ev == EXI_EV_CURRENTDEMAND_RES,
       "decode_header recovers ev 0x12 (CurrentDemandRes)");

    /* pre-check rejects leading 0x24 */
    uint8_t bad[2] = { 0x24, 0x00 };
    exi_decode_init(&d, bad, 2);
    CK(exi_decode_header(&d, &ev) == EXI_ERR_HEADER, "decode_header rejects leading 0x24");
    /* pre-check rejects bit5 set (0xA0 = 10100000, bit5=1) */
    uint8_t bad2[2] = { 0xA0, 0x00 };
    exi_decode_init(&d, bad2, 2);
    CK(exi_decode_header(&d, &ev) == EXI_ERR_HEADER, "decode_header rejects bit5-set leading byte");
    /* event >= 81 -> ERR_EVENT (leading 0x80 ok, event 0x7F=127) */
    uint8_t bad3[2] = { 0x80, 0xFE };   /* 0xFE = 11111110 -> top7 = 127 */
    exi_decode_init(&d, bad3, 2);
    CK(exi_decode_header(&d, &ev) == EXI_ERR_EVENT, "decode_header event>=81 -> ERR_EVENT");
}

int main(void)
{
    test_bits_read();
    test_bits_write();
    test_varlen();
    test_signed();
    test_pvt();
    test_octet();
    test_framing();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}