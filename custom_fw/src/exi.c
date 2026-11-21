/* exi.c — DIN70121 / ISO15118 EXI bit-level codec primitives (REPORT §5.9, Agent E / analyze93).
 * Faithful INERT replica of the C013 generated grammar-table-driven EXI processor's primitive
 * layer (OpenV2G style). Byte-exact MSB-first bit reader/writer + varlen/bool/signed/octet +
 * PhysicalValueType (wire order Multiplier,Unit,Value) + V2GTP framing. Pure logic — no peripheral
 * / power GPIO. No libc mem* (loops). Host-tested (test_exi.c). See E_verified.md / verify_e.py.
 */
#include "exi.h"

void exi_decode_init(exi_stream_t *s, const uint8_t *buf, uint32_t len)
{
    s->buf = (uint8_t *)buf;   /* read-only consumption; cast away const for the shared struct */
    s->cap = len;
    s->pos = 0;
    s->curbyte = 0;
    s->bitsleft = 0;           /* fetch on first read (stock fetch helper 0x0809DA34) */
}

void exi_encode_init(exi_stream_t *s, uint8_t *buf, uint32_t cap, uint32_t start)
{
    s->buf = buf;
    s->cap = cap;
    s->pos = start;            /* reserve the 8-byte V2GTP header (stock TX pos=8) */
    s->curbyte = 0;
    s->bitsleft = 8;           /* stock write-leading-0x80 init: curbyte=0, bitsleft=8 */
}

uint32_t exi_encode_finish(exi_stream_t *s)
{
    /* Flush a partial trailing byte. writeBits accumulates curbyte<<n|val, so the bits written
     * so far sit in the LOW positions; left-align by bitsleft to make the byte MSB-first (EXI
     * pads the unused low bits with 0). Full bytes (bitsleft==0) already flushed MSB-correct. */
    if (s->bitsleft < 8u) {
        uint8_t b = (uint8_t)(s->curbyte << s->bitsleft);
        if (s->pos < s->cap) s->buf[s->pos++] = b;
        s->curbyte = 0;
        s->bitsleft = 8;
    }
    return s->pos;
}

/* readBits core 0x0809DA5E: MSB-first. Single-byte (curbyte>>(bitsleft-n))&(0xFF>>(8-n));
 * multi-byte accumulates *out<<take | next bits. Fetch curbyte=buf[pos++] when bitsleft==0. */
int exi_read_bits(exi_stream_t *s, uint8_t n, uint32_t *out)
{
    uint32_t v = 0;
    if (n == 0) { *out = 0; return EXI_OK; }
    while (n > 0) {
        if (s->bitsleft == 0) {
            if (s->pos >= s->cap) return EXI_ERR_EOF;
            s->curbyte = s->buf[s->pos++];
            s->bitsleft = 8;
        }
        uint8_t take = (n < s->bitsleft) ? n : s->bitsleft;
        uint8_t shift = (uint8_t)(s->bitsleft - take);
        uint32_t mask = (1u << take) - 1u;
        v = (v << take) | ((uint32_t)(s->curbyte >> shift) & mask);
        s->bitsleft = (uint8_t)(s->bitsleft - take);
        n = (uint8_t)(n - take);
    }
    *out = v;
    return EXI_OK;
}

/* writeBits core 0x0809DAE2: MSB-first. curbyte=(curbyte<<take)|v; bitsleft-=take; flush
 * buf[pos++]=curbyte when bitsleft==0, reset curbyte=0/bitsleft=8. */
int exi_write_bits(exi_stream_t *s, uint8_t n, uint32_t val)
{
    if (n == 0) return EXI_OK;
    if (n < 32u) val &= (1u << n) - 1u;
    while (n > 0) {
        uint8_t take = (n < s->bitsleft) ? n : s->bitsleft;
        uint32_t v = (val >> (n - take)) & ((1u << take) - 1u);
        s->curbyte = (uint8_t)((s->curbyte << take) | v);
        s->bitsleft = (uint8_t)(s->bitsleft - take);
        n = (uint8_t)(n - take);
        if (s->bitsleft == 0) {
            if (s->pos >= s->cap) return EXI_ERR_EOF;
            s->buf[s->pos++] = s->curbyte;
            s->curbyte = 0;
            s->bitsleft = 8;
        }
    }
    return EXI_OK;
}

/* bool 0x080934BE: readBits(1); !=0 -> 1. */
int exi_read_bool(exi_stream_t *s, uint8_t *out)
{
    uint32_t b;
    int r = exi_read_bits(s, 1, &b);
    if (r) return r;
    *out = b ? 1u : 0u;
    return EXI_OK;
}
int exi_write_bool(exi_stream_t *s, uint8_t val) { return exi_write_bits(s, 1, val ? 1u : 0u); }

/* unsignedShort varlen 0x08093404: 7-bit groups LSB-first, bit7 continuation (lsrs#7). */
int exi_read_u16(exi_stream_t *s, uint16_t *out)
{
    uint32_t v = 0;
    uint8_t shift = 0;
    for (;;) {
        uint32_t bb;
        int r = exi_read_bits(s, 8, &bb);
        if (r) return r;
        uint8_t b = (uint8_t)bb;
        v |= (uint32_t)(b & 0x7Fu) << shift;
        if (!(b & 0x80u)) break;
        shift = (uint8_t)(shift + 7);
        if (shift >= 28u) break;   /* safety bound (u16 needs <= 3 groups) */
    }
    *out = (uint16_t)v;
    return EXI_OK;
}
int exi_write_u16(exi_stream_t *s, uint16_t val)
{
    uint32_t v = val;
    for (;;) {
        uint8_t b = (uint8_t)(v & 0x7Fu);
        v >>= 7;
        if (v) b |= 0x80u;
        int r = exi_write_bits(s, 8, b);
        if (r) return r;
        if (!v) break;
    }
    return EXI_OK;
}

/* unsignedInt varlen 0x08093432: same 7-bit groups, up to 5 for u32. */
int exi_read_u32(exi_stream_t *s, uint32_t *out)
{
    uint32_t v = 0;
    uint8_t shift = 0;
    for (;;) {
        uint32_t bb;
        int r = exi_read_bits(s, 8, &bb);
        if (r) return r;
        uint8_t b = (uint8_t)bb;
        v |= (uint32_t)(b & 0x7Fu) << shift;
        if (!(b & 0x80u)) break;
        shift = (uint8_t)(shift + 7);
        if (shift >= 35u) break;
    }
    *out = v;
    return EXI_OK;
}
int exi_write_u32(exi_stream_t *s, uint32_t val)
{
    uint32_t v = val;
    for (;;) {
        uint8_t b = (uint8_t)(v & 0x7Fu);
        v >>= 7;
        if (v) b |= 0x80u;
        int r = exi_write_bits(s, 8, b);
        if (r) return r;
        if (!v) break;
    }
    return EXI_OK;
}

/* signed integer 0x080934F0: sign-bit via bool; magnitude via u16 varlen; mvns (ones-complement)
 * if sign set. DIN PVT Value is unsignedShort so the sign-bit is 0 on the wire. */
int exi_read_signed(exi_stream_t *s, int16_t *out)
{
    uint8_t sign;
    int r = exi_read_bool(s, &sign);
    if (r) return r;
    uint16_t mag;
    r = exi_read_u16(s, &mag);
    if (r) return r;
    if (sign) mag = (uint16_t)~mag;
    *out = (int16_t)mag;
    return EXI_OK;
}
int exi_write_signed(exi_stream_t *s, int16_t val)
{
    uint8_t sign = (val < 0) ? 1u : 0u;
    uint16_t mag = (uint16_t)val;
    if (sign) mag = (uint16_t)~mag;
    int r = exi_write_bool(s, sign);
    if (r) return r;
    return exi_write_u16(s, mag);
}

/* n-bit octet string 0x080935D8: varlen length then octets (8 bits each). */
int exi_read_octet(exi_stream_t *s, uint8_t *out, uint16_t cap, uint16_t *len)
{
    uint16_t n;
    int r = exi_read_u16(s, &n);
    if (r) return r;
    if (n > cap) return EXI_ERR_EOF;
    for (uint16_t i = 0; i < n; i++) {
        uint32_t b;
        r = exi_read_bits(s, 8, &b);
        if (r) return r;
        out[i] = (uint8_t)b;
    }
    *len = n;
    return EXI_OK;
}
int exi_write_octet(exi_stream_t *s, const uint8_t *data, uint16_t len)
{
    int r = exi_write_u16(s, len);
    if (r) return r;
    for (uint16_t i = 0; i < len; i++) {
        r = exi_write_bits(s, 8, data[i]);
        if (r) return r;
    }
    return EXI_OK;
}

/* PhysicalValueType decoder 0x08062070 — wire order Multiplier, Unit, Value:
 * Multiplier readBits(3) subs#3 (wire=mult+3, bounded minValue=-3); Unit readBits(2) choice, if 0
 * readBits(4) + bit16 optional-present; Value signed-integer 0x080934F0. */
int exi_read_pvt(exi_stream_t *s, exi_pvt_t *out)
{
    uint32_t m;
    int r = exi_read_bits(s, 3, &m);
    if (r) return r;
    out->mult = (int8_t)((int32_t)m - 3);
    uint32_t choice;
    r = exi_read_bits(s, 2, &choice);
    if (r) return r;
    out->unit = 0;
    out->unit_present = 0;
    if (choice == 0) {
        uint32_t u;
        r = exi_read_bits(s, 4, &u);
        if (r) return r;
        out->unit = (uint8_t)u;
        out->unit_present = 1;   /* orr packed word #0x10000 (bit16 present) */
    }
    int16_t val;
    r = exi_read_signed(s, &val);
    if (r) return r;
    out->value = (uint16_t)val;
    return EXI_OK;
}
int exi_write_pvt(exi_stream_t *s, const exi_pvt_t *v)
{
    int r = exi_write_bits(s, 3, (uint32_t)((int32_t)v->mult + 3));   /* wire = mult+3 */
    if (r) return r;
    if (v->unit_present) {
        r = exi_write_bits(s, 2, 0);          /* choice 0 = Unit present */
        if (r) return r;
        r = exi_write_bits(s, 4, v->unit);
        if (r) return r;
    } else {
        r = exi_write_bits(s, 2, 1);          /* choice 1 = Unit absent */
        if (r) return r;
    }
    return exi_write_signed(s, (int16_t)v->value);
}

/* RX leading-byte pre-check 0x08093C66: read 8 bits, reject 0x24, bit5 test (lsls#0x1a bpl =>
 * bit5 must be clear); then read the 7-bit root event (gate cmp #0x51 = 81). */
int exi_decode_header(exi_stream_t *s, uint8_t *ev)
{
    uint32_t lead;
    int r = exi_read_bits(s, 8, &lead);
    if (r) return r;
    if (lead == 0x24u) return EXI_ERR_HEADER;
    if (lead & 0x20u) return EXI_ERR_HEADER;   /* bit5 set -> err (mvn #0x89) */
    uint32_t e;
    r = exi_read_bits(s, 7, &e);
    if (r) return r;
    if (e >= EXI_EV_COUNT) return EXI_ERR_EVENT;
    *ev = (uint8_t)e;
    return EXI_OK;
}

/* TX write-leading-0x80 0x08093C92 then the 7-bit root event (pos starts after the reserved
 * 8-byte V2GTP header). */
int exi_encode_header(exi_stream_t *s, uint8_t ev)
{
    int r = exi_write_bits(s, 8, EXI_LEADING_BYTE);
    if (r) return r;
    return exi_write_bits(s, 7, ev);
}

/* Inter-field 1-bit event-code gate (analyze103): readBits(1); a set gate shunts to `err`. */
int exi_read_gate(exi_stream_t *s, int err)
{
    uint32_t g;
    int r = exi_read_bits(s, 1, &g);
    if (r) return r;
    return g ? err : EXI_OK;
}
int exi_write_gate(exi_stream_t *s) { return exi_write_bits(s, 1, 0); }

/* DIN document framing (analyze101/102). Encode the ev4d prefix after the leading 0x80 + 7-bit
 * root 0x4D: pre-gate + DIN header (gid 0x6c SessionID + gid 0x6d choice 2) + post-gate + 6-bit
 * message choice. The DIN header SessionID uses the varlen-length + octet-string primitives
 * (0x0809392A + 0x08093B5E == exi_write_octet's u16-varlen length + octets for len < 128). */
int exi_din_encode_doc_start(exi_stream_t *s, uint8_t choice, const uint8_t *sid, uint16_t sid_len)
{
    int r = exi_write_gate(s);                 /* ev4d pre-header gate (0x08070700) */
    if (r) return r;
    r = exi_write_gate(s);                     /* gid 0x6c g1 (0x0806F924) */
    if (r) return r;
    r = exi_write_gate(s);                     /* gid 0x6c g2 (0x0806F930) */
    if (r) return r;
    r = exi_write_octet(s, sid, sid_len);      /* varlen-len + SessionID octets (0x6c) */
    if (r) return r;
    r = exi_write_gate(s);                     /* gid 0x6c g3 (0x0806F950) */
    if (r) return r;
    r = exi_write_bits(s, 2, 2);               /* gid 0x6d choice 2 (DIN; ISO gates clear) */
    if (r) return r;
    r = exi_write_gate(s);                     /* ev4d post-header gate (0x08070718) */
    if (r) return r;
    return exi_write_bits(s, 6, choice);       /* ev03 dispatcher message choice (0x0806D6D2) */
}

/* ev4d trailing EE gate (0x08070732), written after the message body. */
int exi_din_encode_doc_end(exi_stream_t *s) { return exi_write_gate(s); }

/* Decode mirror of exi_din_encode_doc_start: pre-gate + DIN header (returns SessionID) + post-gate
 * + 6-bit subev. The DIN header gid 0x6d choice MUST be 2 (ISO-only extensions absent); the body
 * dispatcher gate is cmp #0x24 (36). Leaves the stream at the body start. */
int exi_din_decode_doc_start(exi_stream_t *s, uint8_t *subev, uint8_t *sid, uint16_t *sid_len)
{
    int r = exi_read_gate(s, EXI_ERR_GATE);    /* ev4d pre-header gate (0x0806A354) */
    if (r) return r;
    r = exi_read_gate(s, EXI_ERR_GATE);        /* gid 0x6c g1 */
    if (r) return r;
    r = exi_read_gate(s, EXI_ERR_GATE);        /* gid 0x6c g2 */
    if (r) return r;
    uint16_t n;
    r = exi_read_octet(s, sid, DIN_SID_MAX, &n);  /* varlen-len + SessionID octets (0x6c) */
    if (r) return r;
    *sid_len = n;
    r = exi_read_gate(s, EXI_ERR_GATE);        /* gid 0x6c g3 */
    if (r) return r;
    uint32_t hd;
    r = exi_read_bits(s, 2, &hd);              /* gid 0x6d choice */
    if (r) return r;
    if (hd != 2u) return EXI_ERR_EVENT;        /* DIN expects choice 2 (no ISO header extension) */
    r = exi_read_gate(s, EXI_ERR_GATE);        /* ev4d post-header gate (0x0806A372) */
    if (r) return r;
    uint32_t sub;
    r = exi_read_bits(s, 6, &sub);             /* body dispatcher subev (0x08066DEA) */
    if (r) return r;
    if (sub >= DIN_BODY_SUBEV_COUNT) return EXI_ERR_EVENT;   /* cmp #0x24 */
    *subev = (uint8_t)sub;
    return EXI_OK;
}