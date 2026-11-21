/* exi.h — DIN70121 / ISO15118 EXI bit-level codec primitives (REPORT §5.9, Agent E / analyze93).
 *
 * Faithful INERT replica of the C013 generated, schema-informed, grammar-table-driven EXI
 * processor (OpenV2G Siemens style). The stock codec is a merged DIN+ISO+XMLDSIG root that reads
 * a 7-bit event and tbb-dispatches to 81 productions; each production is a switch(grammar_id)
 * state machine over a shared primitive layer. This module replicates that PRIMITIVE LAYER
 * byte-exactly (the bit reader/writer + datatypes + PhysicalValueType + framing), which is the
 * load-bearing, fully-recovered part of the grammar. Pure logic — no peripheral / power GPIO.
 *
 * Verified addresses (C013, runtime): readBits core 0x0809DA5E (fetch 0x0809DA34), writeBits core
 * 0x0809DAE2, bool 0x080934BE, u16 varlen 0x08093404, u32 0x08093432, signed 0x080934F0, octet
 * 0x080935D8, PVT decoder 0x08062070 / encoder 0x0806A3AC, decode wrapper 0x08033C24, root decoder
 * 0x0806997A (tbb 0x080699BC, 81 entries), encoder root 0x0806FA9C, leading-0x80 TX 0x08093C92 /
 * RX pre-check 0x08093C66. Bit order MSB-first. See E_verified.md / verify_e.py (52 checks).
 *
 * Bitstream struct (stock {+0 cap, +4 buf, +8 &pos, +0xC curbyte, +0xD bitsleft}); the replica
 * keeps pos by value (functionally identical for a single stream). MSB-first read/write reproduce
 * the stock curbyte>>(bitsleft-n) / curbyte<<n|val semantics byte-for-byte.
 */
#ifndef EXI_H
#define EXI_H
#include <stdint.h>

/* EXI error codes (stock mvn#imm -> negative; subset used by the replica). */
#define EXI_OK            0
#define EXI_ERR_EOF      (-11)   /* 0x0809DA34 fetch past capacity (mvn #0xa)            */
#define EXI_ERR_EVENT    (-108)  /* unknown event / grammar_id (mvn #0x6b)               */
#define EXI_ERR_HEADER   (-137)  /* leading-byte pre-check reject 0x24 (mvn #0x89 path)  */
#define EXI_ERR_EMPTY    (-110)  /* empty-message choice = 1 (mvn #0x6d)                 */
#define EXI_ERR_GATE     (-133)  /* inter-field 1-bit event-code gate != 0 (mvn #0x84)   */
#define EXI_ERR_GRAMMAR  (-500)  /* grammar-state gate error (0xFFFFFE0C)                */

/* Root events (7-bit) for the DIN DC messages — CORRECTED ground-truth numbering (E §1 was
 * +2-shifted in the b-thunk region; rebuilt from the actual tbb path, rebuild_ev_map.py). */
#define EXI_EV_CABLECHECK_RES        0x05u
#define EXI_EV_CURRENTDEMAND_RES     0x12u
#define EXI_EV_DC_EVSE_CHARGE_PARAM  0x15u
#define EXI_EV_DC_EVSE_STATUS        0x16u
#define EXI_EV_CPD_RES_WRAPPER       0x1Du
#define EXI_EV_SESSIONSTOP           0x1Eu
#define EXI_EV_PRECHARGE_RES         0x30u
#define EXI_EV_WELDING_RES           0x4Fu
#define EXI_EV_COUNT                 81u    /* root gate cmp #0x51 */

/* V2GTP framing: [8-byte header][0x80 leading byte][7-bit root event][body]. Payload 0x8001. */
#define EXI_V2GTP_HDR_LEN   8u
#define EXI_LEADING_BYTE    0x80u
#define EXI_PAYLOAD_TYPE    0x8001u

typedef struct {
    uint8_t  *buf;       /* +4 buffer pointer                          */
    uint32_t  cap;       /* +0 capacity (bytes)                        */
    uint32_t  pos;       /* +8 byte position (stock: pointer to counter)*/
    uint8_t   curbyte;   /* +0xC current byte being consumed/built     */
    uint8_t   bitsleft;  /* +0xD bits remaining (read) / free (write)  */
} exi_stream_t;

/* Decode init: consume buf[0..len). curbyte=0, bitsleft=0 (fetch on first read). */
void exi_decode_init(exi_stream_t *s, const uint8_t *buf, uint32_t len);
/* Encode init: build into buf[0..cap). curbyte=0, bitsleft=8, pos=start (reserve V2GTP=8). */
void exi_encode_init(exi_stream_t *s, uint8_t *buf, uint32_t cap, uint32_t start);
/* Flush a partial trailing byte (encode finalization); returns bytes written (pos). */
uint32_t exi_encode_finish(exi_stream_t *s);

/* n-bit unsigned event, MSB-first (readBits core 0x0809DA5E / writeBits 0x0809DAE2). n<=32. */
int exi_read_bits(exi_stream_t *s, uint8_t n, uint32_t *out);
int exi_write_bits(exi_stream_t *s, uint8_t n, uint32_t val);

/* Datatype primitives. */
int exi_read_bool(exi_stream_t *s, uint8_t *out);          /* 0x080934BE: 1 bit -> 0/1     */
int exi_write_bool(exi_stream_t *s, uint8_t val);
int exi_read_u16(exi_stream_t *s, uint16_t *out);          /* 0x08093404: 7-bit varlen     */
int exi_write_u16(exi_stream_t *s, uint16_t val);
int exi_read_u32(exi_stream_t *s, uint32_t *out);          /* 0x08093432: 7-bit varlen     */
int exi_write_u32(exi_stream_t *s, uint32_t val);
int exi_read_signed(exi_stream_t *s, int16_t *out);        /* 0x080934F0: sign+ones-comp   */
int exi_write_signed(exi_stream_t *s, int16_t val);
int exi_read_octet(exi_stream_t *s, uint8_t *out, uint16_t cap, uint16_t *len); /* 0x080935D8 */
int exi_write_octet(exi_stream_t *s, const uint8_t *data, uint16_t len);

/* PhysicalValueType — wire order Multiplier, Unit, Value (decoder 0x08062070). Multiplier is a
 * 3-bit bounded integer (wire = mult+3, minValue=-3); Unit a 4-bit enum gated by a 2-bit choice
 * with bit16 optional-present flag; Value an EXI signed integer (sign-bit 0 for DIN unsignedShort).
 * `mult` is the SIGNED multiplier (-3..3); `unit_present` mirrors the bit16 flag. */
typedef struct {
    int8_t   mult;          /* signed multiplier (wire 3-bit = mult+3) */
    uint8_t  unit;          /* 4-bit unit enum                         */
    uint8_t  unit_present;  /* optional-present (bit16 of packed word) */
    uint16_t value;         /* magnitude (DIN Value is unsignedShort)  */
} exi_pvt_t;
int exi_read_pvt(exi_stream_t *s, exi_pvt_t *out);
int exi_write_pvt(exi_stream_t *s, const exi_pvt_t *val);

/* Framing helpers. Decode: strip the 8-byte V2GTP header (caller passes body), run the leading-byte
 * pre-check (0x08093C66: read 8 bits, reject 0x24, bit5 test) then read the 7-bit root event.
 * Encode: write the leading 0x80 (0x08093C92) then the 7-bit root event (pos starts after the
 * reserved 8-byte V2GTP header). */
int exi_decode_header(exi_stream_t *s, uint8_t *ev);
int exi_encode_header(exi_stream_t *s, uint8_t ev);

#endif /* EXI_H */