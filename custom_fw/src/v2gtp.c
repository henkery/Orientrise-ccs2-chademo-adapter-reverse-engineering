/* v2gtp.c — V2G Transfer Protocol framing (REPORT §5.9, Agent C / analyze92).
 * Byte-exact replica of the C013 V2GTP header helpers (0x0802134C / 0x0808522E / 0x080212C2).
 * INERT: pure framing logic, no network I/O. Host-unit-tested (test_v2gtp.c).
 */
#include "v2gtp.h"

uint16_t v2gtp_encode(uint8_t *buf, uint16_t payload_len, uint16_t type)
{
    /* 0x0808522E: [0]=1,[1]=0xFE,[2]=type>>8,[3]=type&0xFF,[4..7]=len BE (rev + str). */
    buf[0] = V2GTP_VER;
    buf[1] = V2GTP_INV;
    buf[2] = (uint8_t)(type >> 8);
    buf[3] = (uint8_t)(type & 0xFFu);
    uint32_t l = (uint32_t)payload_len;
    buf[4] = (uint8_t)(l >> 24);
    buf[5] = (uint8_t)(l >> 16);
    buf[6] = (uint8_t)(l >> 8);
    buf[7] = (uint8_t)(l);
    return (uint16_t)(payload_len + V2GTP_HDR_LEN);
}

uint16_t v2gtp_parse(const uint8_t *buf, uint16_t len, uint16_t *payload_len)
{
    /* 0x080212C2: ldr [4]; rev; +8; cmp len -> blo fail ; [0]==1 ; [1]==0xFE ; ldrh [2].
     * The stock returns the type byte-swapped (ldrh LE); we normalize to wire order. */
    if (len < V2GTP_HDR_LEN) {
        return 0;
    }
    uint32_t l = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                 ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
    if ((uint32_t)len < l + V2GTP_HDR_LEN) {
        return 0;
    }
    if (buf[0] != V2GTP_VER || buf[1] != V2GTP_INV) {
        return 0;
    }
    if (payload_len) {
        *payload_len = (uint16_t)l;
    }
    return (uint16_t)(((uint16_t)buf[2] << 8) | (uint16_t)buf[3]);
}