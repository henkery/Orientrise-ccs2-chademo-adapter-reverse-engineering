/* test_revert.c — host unit test for the revert-from-custom xPAI/UPG core
 * (custom_fw/src/revert.c, REPORT §5.15c, byte-derived boot f+0x1108 / f+0x1eca / f+0x1cc8).
 *
 * Build + run (host gcc; freestanding module, no library deps):
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_revert \
 *       test_revert.c src/revert.c && ./test_revert'
 *
 * Verifies: CRC16/MODBUS check value + residue property; the xPAI descriptor build/validate
 * round-trip (magic, magic2, length bounds, XOR-of-16-words checksum) and rejection of each
 * corrupted field; the filesize+2 length convention against the boot bound f+0x1f76; the UPG
 * header check (key-echo nonzero, XOR-decode, "XIE2", footer CRC residue, length bound) on a
 * synthetic image AND the real stock SERVICE.UPG; and rejection of corrupted UPG headers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "revert.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Build a synthetic raw obfuscated UPG of `filesize` bytes with a valid decoded header:
 * "XIE2" @0x3E8, length field @0x3F0 = filesize-0x404, footer CRC16/MODBUS @0x3FC.
 * key0/key1 are the leading key-echo (both nonzero). Returns a malloc'd buffer (caller frees). */
static uint8_t *synth_upg(uint32_t filesize, uint8_t key0, uint8_t key1)
{
    uint8_t *raw = (uint8_t *)malloc(filesize);
    memset(raw, 0, filesize);
    raw[0] = key0;
    raw[1] = key1;

    uint8_t h[REVERT_UPG_HDR];
    memset(h, 0, sizeof h);
    h[REVERT_XIE2_OFF + 0] = 0x58;   /* X */
    h[REVERT_XIE2_OFF + 1] = 0x49;   /* I */
    h[REVERT_XIE2_OFF + 2] = 0x45;   /* E */
    h[REVERT_XIE2_OFF + 3] = 0x32;   /* 2 */
    uint32_t length_field = filesize - REVERT_UPG_HDR - 2u;   /* filesize - 0x404 */
    h[REVERT_LEN_OFF + 0] = (uint8_t)(length_field & 0xFFu);
    h[REVERT_LEN_OFF + 1] = (uint8_t)((length_field >> 8) & 0xFFu);
    h[REVERT_LEN_OFF + 2] = (uint8_t)((length_field >> 16) & 0xFFu);
    h[REVERT_LEN_OFF + 3] = (uint8_t)((length_field >> 24) & 0xFFu);
    uint16_t fc = revert_crc16_modbus(h + REVERT_FOOT_LO, REVERT_FOOT_CRC_OFF - REVERT_FOOT_LO);
    h[REVERT_FOOT_CRC_OFF + 0] = (uint8_t)(fc & 0xFFu);
    h[REVERT_FOOT_CRC_OFF + 1] = (uint8_t)(fc >> 8);

    for (uint32_t i = 0; i < REVERT_UPG_HDR; i++) {
        uint8_t b = (uint8_t)(h[i] ^ key0);
        if (i & 1u)
            b = (uint8_t)(b ^ key1);
        raw[REVERT_UPG_KEYEcho + i] = b;
    }
    /* app region: obfuscated 0xFF filler (the header check does not inspect it) */
    for (uint32_t j = REVERT_UPG_HDR + REVERT_UPG_KEYEcho; j < filesize; j++) {
        uint8_t b = (uint8_t)(0xFFu ^ key0);
        if ((j - REVERT_UPG_KEYEcho) & 1u)
            b = (uint8_t)(b ^ key1);
        raw[j] = b;
    }
    return raw;
}

int main(void)
{
    uint8_t desc[REVERT_DESC_SIZE];

    /* --- CRC16/MODBUS standard check value: "123456789" -> 0x4B37 --- */
    CHECK(revert_crc16_modbus((const uint8_t *)"123456789", 9) == 0x4B37,
          "crc16/modbus check value 0x4B37");
    /* residue property: CRC over data+crc(LE) == 0 */
    {
        uint8_t buf[11];
        memcpy(buf, "123456789", 9);
        uint16_t c = revert_crc16_modbus(buf, 9);
        buf[9] = (uint8_t)(c & 0xFFu);
        buf[10] = (uint8_t)(c >> 8);
        CHECK(revert_crc16_modbus(buf, 11) == 0, "crc16/modbus residue over data+crc == 0");
    }

    /* --- length convention: xPAI len = filesize + 2 --- */
    CHECK(revert_xpai_len_for(595140u) == 595142u, "xpai_len_for(SERVICE.UPG) = filesize+2");
    CHECK(revert_xpai_len_for(0x1000u) == 0x1002u, "xpai_len_for(0x1000) = 0x1002");

    /* --- xPAI build/validate round-trip across the length range --- */
    CHECK(revert_xpai_build(desc, REVERT_LEN_MIN) == 0, "build len min 0x72C ok");
    CHECK(revert_xpai_validate(desc) == 0, "validate len min ok");
    CHECK(rd32(desc + 0x00) == REVERT_XPAI_MAGIC, "desc word0 = xPAI magic");
    CHECK(rd32(desc + 0x04) == REVERT_XPAI_MAGIC2, "desc word1 = 0xABCDEF12");
    CHECK(rd32(desc + 0x38) == REVERT_LEN_MIN, "desc word14 = len");
    {
        uint32_t x = 0;
        for (int i = 0; i < 16; i++)
            x ^= rd32(desc + i * 4);
        CHECK(x == 0, "desc XOR of all 16 words == 0");
        CHECK(rd32(desc + 0x3C) == (REVERT_XPAI_MAGIC ^ REVERT_XPAI_MAGIC2 ^ REVERT_LEN_MIN),
              "desc word15 = XOR(words[0..14])");
    }
    CHECK(revert_xpai_build(desc, REVERT_LEN_MAX) == 0, "build len max 0xE0404 ok");
    CHECK(revert_xpai_validate(desc) == 0, "validate len max ok");
    CHECK(revert_xpai_build(desc, revert_xpai_len_for(595140u)) == 0, "build SERVICE.UPG len ok");
    CHECK(revert_xpai_validate(desc) == 0, "validate SERVICE.UPG len ok");
    /* words[2..13] are zero */
    {
        int zero = 1;
        for (int i = 2; i <= 13; i++)
            if (rd32(desc + i * 4) != 0)
                zero = 0;
        CHECK(zero, "desc words[2..13] == 0");
    }

    /* --- xPAI build rejects out-of-bounds lengths --- */
    CHECK(revert_xpai_build(desc, REVERT_LEN_MIN - 1u) == -1, "build rejects len < 0x72C");
    CHECK(revert_xpai_build(desc, REVERT_LEN_MAX + 1u) == -1, "build rejects len > 0xE0404");
    CHECK(revert_xpai_build(desc, 0) == -1, "build rejects len 0");

    /* --- xPAI validate rejects each corrupted field (boot f+0x1108) --- */
    revert_xpai_build(desc, 0x10000u);
    desc[0] ^= 0x01;                          /* corrupt magic */
    CHECK(revert_xpai_validate(desc) == -1, "validate rejects bad magic");
    revert_xpai_build(desc, 0x10000u);
    desc[4] ^= 0x01;                          /* corrupt magic2 */
    CHECK(revert_xpai_validate(desc) == -1, "validate rejects bad magic2");
    revert_xpai_build(desc, 0x10000u);
    desc[0x38] ^= 0x01;                       /* corrupt len (also breaks XOR) */
    CHECK(revert_xpai_validate(desc) == -1, "validate rejects bad len/XOR");
    revert_xpai_build(desc, 0x10000u);
    desc[0x3C] ^= 0x01;                       /* corrupt checksum only */
    CHECK(revert_xpai_validate(desc) == -1, "validate rejects bad XOR checksum");
    /* len below bound but XOR repaired -> still rejected on bounds */
    revert_xpai_build(desc, 0x10000u);
    {
        uint32_t w[16];
        for (int i = 0; i < 16; i++)
            w[i] = rd32(desc + i * 4);
        w[14] = REVERT_LEN_MIN - 1u;
        uint32_t x = 0;
        for (int i = 0; i < 15; i++)
            x ^= w[i];
        w[15] = x;
        for (int i = 0; i < 16; i++) {
            desc[i * 4 + 0] = (uint8_t)(w[i] & 0xFFu);
            desc[i * 4 + 1] = (uint8_t)((w[i] >> 8) & 0xFFu);
            desc[i * 4 + 2] = (uint8_t)((w[i] >> 16) & 0xFFu);
            desc[i * 4 + 3] = (uint8_t)((w[i] >> 24) & 0xFFu);
        }
    }
    CHECK(revert_xpai_validate(desc) == -1, "validate rejects len < min even with valid XOR");

    /* --- synthetic UPG header check (boot f+0x1eca) --- */
    {
        uint32_t fs = 0x1000u;
        uint8_t *upg = synth_upg(fs, 0x25, 0xA8);
        uint32_t len = revert_xpai_len_for(fs);
        CHECK(revert_upg_check(upg, len) == 0, "synthetic UPG accepted");
        /* the xPAI length passes the boot bound: (len-2) > (length_field+0x402) */
        CHECK((len - 2u) > ((fs - 0x404u) + 0x402u), "boot length bound satisfied (len=filesize+2)");
        /* a filesize-length xPAI would FAIL the boot bound (strict >): (fs-2) > (fs-2) is false */
        CHECK(!((fs - 2u) > ((fs - 0x404u) + 0x402u)), "len=filesize would fail boot bound (needs +2)");

        /* corrupt key-echo -> rejected */
        upg[0] = 0;
        CHECK(revert_upg_check(upg, len) == -1, "UPG rejects key0 == 0");
        upg[0] = 0x25; upg[1] = 0;
        CHECK(revert_upg_check(upg, len) == -1, "UPG rejects key1 == 0");
        upg[1] = 0xA8;
        CHECK(revert_upg_check(upg, len) == 0, "UPG re-accepted after key restore");

        /* corrupt the XIE2 magic (decoded[0x3E8] = raw[0x3EA], even index ^key0) */
        upg[REVERT_UPG_KEYEcho + REVERT_XIE2_OFF] ^= 0x01;
        CHECK(revert_upg_check(upg, len) == -1, "UPG rejects bad XIE2 magic");
        upg[REVERT_UPG_KEYEcho + REVERT_XIE2_OFF] ^= 0x01;

        /* corrupt a footer byte -> CRC residue nonzero -> rejected */
        upg[REVERT_UPG_KEYEcho + REVERT_FOOT_LO] ^= 0x01;
        CHECK(revert_upg_check(upg, len) == -1, "UPG rejects bad footer CRC");
        upg[REVERT_UPG_KEYEcho + REVERT_FOOT_LO] ^= 0x01;
        CHECK(revert_upg_check(upg, len) == 0, "UPG re-accepted after footer restore");

        /* length bound failure: pass len = filesize (not +2) -> (len-2)==length_field+0x402 -> fail */
        CHECK(revert_upg_check(upg, fs) == -1, "UPG rejects len=filesize (bound strict >)");

        /* too-short buffer -> rejected */
        CHECK(revert_upg_check(upg, 0x403u) == -1, "UPG rejects len < 0x404");
        CHECK(revert_upg_check(NULL, len) == -1, "UPG rejects NULL");
        free(upg);
    }

    /* --- real stock SERVICE.UPG (../SERVICE.UPG relative to custom_fw/) --- */
    {
        FILE *f = fopen("../SERVICE.UPG", "rb");
        if (!f) {
            printf("note: ../SERVICE.UPG not found — skipping real-image checks\n");
        } else {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            uint8_t *upg = (uint8_t *)malloc((size_t)sz);
            size_t got = fread(upg, 1, (size_t)sz, f);
            fclose(f);
            CHECK(got == (size_t)sz, "SERVICE.UPG fully read");
            CHECK(sz == 595140, "SERVICE.UPG size 595140");
            CHECK(upg[0] != 0 && upg[1] != 0, "SERVICE.UPG key-echo nonzero");
            uint32_t len = revert_xpai_len_for((uint32_t)sz);
            CHECK(revert_upg_check(upg, len) == 0, "real SERVICE.UPG header accepted by boot-mirror");
            CHECK(revert_xpai_build(desc, len) == 0, "xPAI build for real SERVICE.UPG ok");
            CHECK(revert_xpai_validate(desc) == 0, "xPAI validate for real SERVICE.UPG ok");
            CHECK(rd32(desc + 0x38) == len, "xPAI word14 == SERVICE.UPG len (filesize+2)");
            free(upg);
        }
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}