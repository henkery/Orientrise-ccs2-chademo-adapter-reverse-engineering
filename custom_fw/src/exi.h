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

/* DIN document model (analyze101/102 — CORRECTS the earlier per-message-root model). ALL DIN
 * messages (Req AND Res) ride a SINGLE 7-bit root event 0x4D (ev4d), followed by a DIN header
 * (gid 0x6c SessionID + gid 0x6d) and a 6-bit message choice. The body dispatcher 0x08066DD0
 * (readBits6, cmp #0x24 = 36, tbb 0x08066E06) interleaves the Req and Res productions by their
 * 6-bit code. The former EXI_EV_* "root events" were the production grammar-ids (ev05/ev12/…),
 * NOT wire root events — the wire root is always 0x4D. Encode chain: encoder root 0x0806FA9C
 * (W40 bit1 DIN gate) -> writeBits(7,0x4D) -> ev4d 0x080706F6 (pre-gate + header-sub 0x0806F8FC
 * + post-gate + ev03 dispatcher 0x0806D6D2 writeBits(6,choice) + EE gate). Decode mirror: root
 * decoder 0x0806997A (readBits7, cmp#0x51) -> ev4d 0x0806A33E -> Header 0x0806978A -> body
 * dispatcher 0x08066DD0 (readBits6 subev) -> production. */
#define EXI_DIN_ROOT                 0x4Du  /* 7-bit DIN document root event (ev4d)            */
#define EXI_EV_COUNT                 81u    /* root gate cmp #0x51                             */
#define DIN_BODY_SUBEV_COUNT         36u    /* body dispatcher gate cmp #0x24                  */

/* Req message choices (6-bit; encoder ev03 dispatcher 0x0806D6D2, analyze101 Group E). */
#define DIN_REQ_CABLECHECK           0x01u  /* ev04 0x0806D698 */
#define DIN_REQ_CPD                  0x07u  /* ev0b 0x0806CEF0 */
#define DIN_REQ_CURRENTDEMAND        0x0Du  /* ev11 0x0806BDDC */
#define DIN_REQ_POWERDELIVERY        0x13u  /* ev2d 0x0806B814 */
#define DIN_REQ_PRECHARGE            0x15u  /* ev2f 0x0806B4DE */
#define DIN_REQ_SERVICEDISCOVERY     0x19u  /* ev3c 0x0806B06A */
#define DIN_REQ_SESSIONSETUP         0x1Du  /* ev40 0x0806ABEA */
#define DIN_REQ_SESSIONSTOP          0x1Fu  /* ev42 0x0806AB0E */
#define DIN_REQ_WELDING              0x21u  /* ev4e 0x0806AA92 */

/* Res message sub-events (6-bit; decoder body dispatcher tbb 0x08066E06, analyze102). */
#define DIN_RES_CABLECHECK           0x02u  /* ev05 0x08066C5C */
#define DIN_RES_CPD                  0x08u  /* ev0c 0x08065BFC */
#define DIN_RES_CURRENTDEMAND        0x0Eu  /* ev12 0x0806471E */
#define DIN_RES_POWERDELIVERY        0x14u  /* ev2e 0x08063DBA */
#define DIN_RES_PRECHARGE            0x16u  /* ev30 0x08063A8A */
#define DIN_RES_SERVICEDISCOVERY     0x1Au  /* ev3d 0x08063370 */
#define DIN_RES_SESSIONSETUP         0x1Eu  /* ev41 0x08062B1E */
#define DIN_RES_SESSIONSTOP          0x20u  /* ev43 0x08062A7E */
#define DIN_RES_WELDING              0x22u  /* ev4f 0x08062754 */

/* DIN header SessionID (gid 0x6c) — hexBinary octet string. Stock SessionSetupReq uses a 1-byte
 * 0x00 placeholder; post-setup builders copy the negotiated SessionID. Bounded for the replica. */
#define DIN_SID_MAX                  8u

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
 * reserved 8-byte V2GTP header). For DIN the root event is always EXI_DIN_ROOT (0x4D); the message
 * is then selected by the 6-bit choice/subev handled by the DIN document layer below. */
int exi_decode_header(exi_stream_t *s, uint8_t *ev);
int exi_encode_header(exi_stream_t *s, uint8_t ev);

/* Inter-field 1-bit event-code gates (analyze103). Every DIN sub-production field is bracketed by
 * 1-bit gates that MUST be 0 on the wire; a set gate shunts to the grammar's error code. */
int exi_read_gate(exi_stream_t *s, int err);   /* readBits(1); !=0 -> err (e.g. -133/-110/-500) */
int exi_write_gate(exi_stream_t *s);           /* writeBits(1, 0)                               */

/* DIN document framing (analyze101/102), the layer AFTER exi_encode_header/exi_decode_header has
 * written/read the leading 0x80 + 7-bit root 0x4D. Wire layout (ev4d 0x080706F6 / 0x0806A33E):
 *   [1-bit pre-gate] [DIN header] [1-bit post-gate] [6-bit choice/subev] [body] [1-bit EE gate]
 * DIN header (header-sub 0x0806F8FC): gid 0x6c SessionID = [1-bit g][1-bit g][varlen-len][SID
 * octets][1-bit g], then gid 0x6d = [2-bit choice 2] (both ISO-only gates clear in DIN; the clear
 * helper 0x08061D5C zeroes doc+0x54 / doc+0x13F8 so every DIN builder ends writeBits(2,2)).
 * Encode: exi_din_encode_doc_start writes pre-gate + header + post-gate + 6-bit choice (stream then
 * at body start); the caller writes the body; exi_din_encode_doc_end writes the EE gate.
 * Decode: exi_din_decode_doc_start reads pre-gate + header (returns SessionID) + post-gate + 6-bit
 * subev (stream then at body start); the caller decodes the body; the trailing EE gate is the final
 * 1-bit (exi_read_gate). Returns EXI_OK / negative EXI error. */
int exi_din_encode_doc_start(exi_stream_t *s, uint8_t choice, const uint8_t *sid, uint16_t sid_len);
int exi_din_encode_doc_end(exi_stream_t *s);
int exi_din_decode_doc_start(exi_stream_t *s, uint8_t *subev, uint8_t *sid, uint16_t *sid_len);

#endif /* EXI_H */