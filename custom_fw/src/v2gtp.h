/* v2gtp.h — V2G Transfer Protocol framing (REPORT §5.9, Agent C / analyze92).
 *
 * Byte-exact replica of the C013 V2GTP header helpers that wrap every SDP + EXI message:
 *   encoder (SDP)  0x0802134C : [0]=0x01,[1]=0xFE,[2..3]=type,[4..7]=len BE ; ret payload_len+8
 *   writer  (EXI)  0x0808522E : [0]=0x01,[1]=0xFE,[2]=type>>8,[3]=type&0xFF,[4..7]=len BE
 *   parser         0x080212C2 : len>=payloadlen+8 && [0]==1 && [1]==0xFE -> type (else 0)
 *
 * Wire header (8 bytes): ver=0x01, inv=0xFE, payload-type u16 BIG-endian, payload-len u32
 * BIG-endian, then the payload. Payload types: 0x8001 EXI V2G message, 0x9000 SDP request,
 * 0x9001 SDP response. (The stock parser returns the type byte-swapped — ldrh LE of [2..3] —
 * so downstream compares use 0x0180/0x0190; this replica normalizes to the wire type and the
 * host test checks the on-wire bytes.)
 *
 * INERT: pure framing logic, host-unit-tested (custom_fw/test_v2gtp.c). No network I/O here.
 */
#ifndef V2GTP_H
#define V2GTP_H
#include <stdint.h>

#define V2GTP_VER          0x01u
#define V2GTP_INV          0xFEu
#define V2GTP_HDR_LEN      8u
#define V2GTP_TYPE_EXI     0x8001u   /* EXI V2G message (appHandshake / DIN / ISO) */
#define V2GTP_TYPE_SDP_REQ 0x9000u   /* SECC Discovery Protocol request            */
#define V2GTP_TYPE_SDP_RES 0x9001u   /* SECC Discovery Protocol response           */

/* Write the 8-byte header in front of an already-placed payload (buf[8..8+payload_len)).
 * `type` is the full wire type (e.g. 0x8001). Returns total frame length = payload_len + 8.
 * Mirrors 0x0808522E (big-endian type + length). */
uint16_t v2gtp_encode(uint8_t *buf, uint16_t payload_len, uint16_t type);

/* Validate a V2GTP frame. Returns the wire payload type (0x8001/0x9000/0x9001/…) or 0 if the
 * header is invalid or the buffer is shorter than payload_len+8. On success *payload_len is the
 * decoded payload length. Mirrors 0x080212C2 (normalized to wire byte order). */
uint16_t v2gtp_parse(const uint8_t *buf, uint16_t len, uint16_t *payload_len);

#endif /* V2GTP_H */