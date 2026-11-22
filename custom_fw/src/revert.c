/* revert.c — revert-from-custom aid: pure xPAI/UPG build + validation core (REPORT §5.15c).
 *
 * Mirrors the boot's update-command validation byte-for-byte so a descriptor/UPG this module accepts
 * is one the boot will accept:
 *   revert_xpai_validate  <-> boot f+0x1108  (magic, magic2, length bounds, XOR-of-16-words == 0)
 *   revert_upg_check      <-> boot f+0x1eca  (key-echo nonzero, XOR-decode header, "XIE2", footer
 *                                             CRC16/MODBUS residue 0, length bound f+0x1f76)
 *   revert_crc16_modbus   <-> boot f+0x1cc8  (poly 0x8005 reflected 0xA001, init 0xFFFF, xorout 0)
 *
 * The SPI staging + reset path (hardware) is added separately on top of spi4.c write ops; this file
 * is freestanding and host-unit-tested (custom_fw/test_revert.c).
 */
#include "revert.h"

uint16_t revert_crc16_modbus(const uint8_t *d, uint32_t n)
{
    uint16_t c = 0xFFFFu;
    for (uint32_t i = 0; i < n; i++) {
        c = (uint16_t)(c ^ d[i]);
        for (int k = 0; k < 8; k++)
            c = (c & 1u) ? (uint16_t)((c >> 1) ^ 0xA001u) : (uint16_t)(c >> 1);
    }
    return c;
}

uint32_t revert_xpai_len_for(uint32_t filesize)
{
    /* Boot bound f+0x1f76: (len-2) > (length_field+0x402), length_field = filesize-0x404.
     * => len > filesize. filesize+2 is the minimal passing value (decodes the full image). */
    return filesize + 2u;
}

int revert_xpai_build(uint8_t out[REVERT_DESC_SIZE], uint32_t upg_len)
{
    if (upg_len < REVERT_LEN_MIN || upg_len > REVERT_LEN_MAX)
        return -1;

    uint32_t w[16];
    for (int i = 0; i < 16; i++)
        w[i] = 0;
    w[0]  = REVERT_XPAI_MAGIC;
    w[1]  = REVERT_XPAI_MAGIC2;
    w[14] = upg_len;

    uint32_t x = 0;
    for (int i = 0; i < 15; i++)
        x ^= w[i];
    w[15] = x;                       /* XOR of all 16 words == 0 */

    for (int i = 0; i < 16; i++) {
        out[i * 4 + 0] = (uint8_t)(w[i] & 0xFFu);
        out[i * 4 + 1] = (uint8_t)((w[i] >> 8) & 0xFFu);
        out[i * 4 + 2] = (uint8_t)((w[i] >> 16) & 0xFFu);
        out[i * 4 + 3] = (uint8_t)((w[i] >> 24) & 0xFFu);
    }
    return 0;
}

int revert_xpai_validate(const uint8_t desc[REVERT_DESC_SIZE])
{
    uint32_t w[16];
    uint32_t x = 0;
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)desc[i * 4 + 0]
             | ((uint32_t)desc[i * 4 + 1] << 8)
             | ((uint32_t)desc[i * 4 + 2] << 16)
             | ((uint32_t)desc[i * 4 + 3] << 24);
        x ^= w[i];
    }
    if (w[0] != REVERT_XPAI_MAGIC)                 /* boot f+0x1108 magic   */
        return -1;
    if (w[1] != REVERT_XPAI_MAGIC2)                /* boot f+0x1108 magic2  */
        return -1;
    if (w[14] < REVERT_LEN_MIN || w[14] > REVERT_LEN_MAX)  /* length bounds */
        return -1;
    if (x != 0)                                    /* XOR of all 16 words   */
        return -1;
    return 0;
}

int revert_upg_check(const uint8_t *upg, uint32_t len)
{
    /* Need the 2-byte key-echo + the 0x400-byte obfuscated header. */
    if (!upg || len < (REVERT_UPG_HDR + REVERT_UPG_KEYEcho))
        return -1;

    uint8_t key0 = upg[0];
    uint8_t key1 = upg[1];
    if (key0 == 0 || key1 == 0)                    /* boot f+0x1f08 / f+0x1f0e */
        return -1;

    /* XOR-decode the 0x400-byte header from upg[2..0x402): h[i] = upg[2+i]^key0, odd i ^= key1. */
    uint8_t h[REVERT_UPG_HDR];
    for (uint32_t i = 0; i < REVERT_UPG_HDR; i++) {
        uint8_t b = (uint8_t)(upg[REVERT_UPG_KEYEcho + i] ^ key0);
        if (i & 1u)
            b = (uint8_t)(b ^ key1);
        h[i] = b;
    }

    /* "XIE2" @ decoded[0x3E8] (58 49 45 32). */
    if (h[REVERT_XIE2_OFF + 0] != 0x58 || h[REVERT_XIE2_OFF + 1] != 0x49 ||
        h[REVERT_XIE2_OFF + 2] != 0x45 || h[REVERT_XIE2_OFF + 3] != 0x32)
        return -1;

    /* CRC16/MODBUS residue 0 over decoded[0x3E8..0x3FE) (0x16 bytes, includes the stored footer CRC). */
    if (revert_crc16_modbus(h + REVERT_FOOT_LO, REVERT_FOOT_HI - REVERT_FOOT_LO) != 0)
        return -1;

    /* Length bound f+0x1f76: (len-2) > (length_field + 0x402), length_field = decoded[0x3F0] LE32. */
    uint32_t length_field = (uint32_t)h[REVERT_LEN_OFF + 0]
                          | ((uint32_t)h[REVERT_LEN_OFF + 1] << 8)
                          | ((uint32_t)h[REVERT_LEN_OFF + 2] << 16)
                          | ((uint32_t)h[REVERT_LEN_OFF + 3] << 24);
    if ((len - 2u) <= (length_field + REVERT_UPG_HDR))
        return -1;

    return 0;
}