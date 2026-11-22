/* din70121.c — DIN70121 DC application layer (EVCC), REPORT §5.9, Agent D / analyze92.
 * Faithful INERT replica of the C013 EVSE-measurement extraction + CurrentDemand actuation field
 * maps + the corrected power-of-10 PhysicalValueType scaling. Communication only — no power GPIO.
 * Pure scaling/decode/encode/setter host-tested (test_din70121.c). No libc mem* (loops).
 */
#include "din70121.h"

static din_meas_t meas;

static void z(uint8_t *p, uint16_t n) { for (uint16_t i = 0; i < n; i++) p[i] = 0; }
static uint16_t ld16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8)); }
static void st16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v & 0xFFu); p[1] = (uint8_t)(v >> 8); }

/* Power-of-10 table (the converter 0x0804E786 / DIN helper 0x0802B92C lookup). */
static const uint32_t pow10_tab[7] = { 1u, 10u, 100u, 1000u, 10000u, 100000u, 1000000u };

uint32_t din_pow10(int8_t code)
{
    /* 0x0804E786: cmp #7 ; blt -> table[code] ; else movs #0xff. The caller sxtb's the byte.
     * Valid factor range [0,6] (multiplier -3..+3). >=7 -> 0xFF; <0 is out-of-table (safe 0xFF). */
    int32_t x = (int32_t)code;
    if (x >= 0 && x < 7) return pow10_tab[x];
    return 0xFFu;
}

uint16_t din_scale(uint16_t raw, int8_t factor)
{
    /* muls raw*pow10(factor) (low 32) ; udiv /1000 ; strh low16. real = raw*10^(factor-3). */
    uint32_t f = din_pow10(factor);
    uint32_t prod = (uint32_t)raw * f;
    return (uint16_t)(prod / 1000u);
}

void din_cd_res_decode(const uint8_t *exi, din_meas_t *m)
{
    /* 0x0802DC0A: meas <- EXI field map; stored factor = wire multiplier + 3.
     * Optional-present fallbacks (EXI[0x24]/[0x30] bit0) are honored: when clear, the stock
     * keeps the previously-stored CPD value — here we keep the existing meas field. */
    m->evse_present_voltage   = ld16(exi + DIN_CDR_EXI_PRESENT_V);
    m->evse_present_voltage_f = (int8_t)(exi[DIN_CDR_EXI_PRESENT_V_F] + 3);
    m->evse_present_current   = ld16(exi + DIN_CDR_EXI_PRESENT_I);
    m->evse_present_current_f = (int8_t)(exi[DIN_CDR_EXI_PRESENT_I_F] + 3);

    if (exi[0x24] & 1u) {   /* EVSEMaximumVoltageLimit present */
        m->evse_max_voltage   = ld16(exi + DIN_CDR_EXI_MAX_V);
        m->evse_max_voltage_f = (int8_t)(exi[DIN_CDR_EXI_MAX_V_F] + 3);
    }
    if (exi[0x2A] & 1u) {   /* EVSEMaximumCurrentLimit present (EXI[0x28] value, [0x26] factor) */
        m->evse_max_current   = ld16(exi + DIN_CDR_EXI_MAX_I);
        m->evse_max_current_f = (int8_t)(exi[DIN_CDR_EXI_MAX_I_F] + 3);
    }
    m->current_limit_achieved = exi[DIN_CDR_EXI_CUR_ACHIEVED];
    m->voltage_limit_achieved = exi[DIN_CDR_EXI_VOL_ACHIEVED];
    m->power_limit_achieved   = exi[DIN_CDR_EXI_PWR_ACHIEVED];
}

uint16_t din_evse_max_current_a(const din_meas_t *m)
{
    return din_scale(m->evse_max_current, m->evse_max_current_f);
}
uint16_t din_evse_present_current_a(const din_meas_t *m)
{
    return din_scale(m->evse_present_current, m->evse_present_current_f);
}
uint16_t din_evse_max_voltage_v(const din_meas_t *m)
{
    return din_scale(m->evse_max_voltage, m->evse_max_voltage_f);
}
uint16_t din_evse_present_voltage_v(const din_meas_t *m)
{
    return din_scale(m->evse_present_voltage, m->evse_present_voltage_f);
}

void din_set_ev_target(din_meas_t *m, uint16_t current, uint16_t voltage, uint8_t packed_factors)
{
    /* 0x0802B8F6 (setter arm 0x606): meas[0x3CE0]=current ; [0x3CE2]=voltage ;
     * [0x3CE4]=packed&7 ; [0x3CE5]=(packed>>3)&7. Factors stored as multiplier+3. */
    m->ev_target_current   = current;
    m->ev_target_voltage   = voltage;
    m->ev_target_current_f = (uint8_t)(packed_factors & 7u);
    m->ev_target_voltage_f = (uint8_t)((packed_factors >> 3) & 7u);
}

void din_cd_req_encode(din_meas_t *m, uint8_t *exi)
{
    /* 0x0802C2CE / excerpt 0x0802C406 (offsets CORRECTED by analyze101): EVTargetCurrent
     * meas[0x3CE0]->EXI[0x14], factor-3->[0x18]; EVTargetVoltage meas[0x3CE2]->EXI[0x64],
     * factor-3->[0x68]; BulkChargingComplete meas[0x3CB7]->EXI[0x40] (gate [0x44]=1),
     * ChargingComplete meas[0x3CB8]->EXI[0x48]. Wire factor = stored factor - 3. */
    z(exi, DIN_CDQ_TX_LEN);
    st16(exi + DIN_CDQ_EXI_TARGET_I, m->ev_target_current);
    exi[DIN_CDQ_EXI_TARGET_I_F] = (uint8_t)(m->ev_target_current_f - 3u);
    st16(exi + DIN_CDQ_EXI_TARGET_V, m->ev_target_voltage);
    exi[DIN_CDQ_EXI_TARGET_V_F] = (uint8_t)(m->ev_target_voltage_f - 3u);
    exi[DIN_CDQ_EXI_BULK_COMPLETE] = m->bulk_charging_complete;
    exi[DIN_CDQ_EXI_BULK_GATE]     = 1u;
    exi[DIN_CDQ_EXI_CHG_COMPLETE]  = m->charging_complete;
    m->first_demand_sent = 1u;   /* meas[0x243] set on first encode (0x0802C436) */
}

void din70121_init(void)
{
    z((uint8_t *)&meas, sizeof meas);
    /* Default factors = multiplier 0 -> stored 3 (so scale is identity until the EVSE supplies
     * real PhysicalValues). Zero values keep the inert replica commanding nothing. */
    meas.evse_max_voltage_f     = 3;
    meas.evse_present_current_f = 3;
    meas.evse_present_voltage_f = 3;
    meas.evse_max_current_f     = 3;
    meas.ev_target_current_f    = 3;
    meas.ev_target_voltage_f    = 3;
}

const din_meas_t *din70121_meas(void) { return &meas; }
din_meas_t *din70121_meas_mut(void) { return &meas; }

/* ---- EXI grammar message codec (Agent E / analyze93; bit-level via exi.c) ---- */

/* PVT -> meas value + factor (application convention: stored factor = signed mult + 3). */
static void pvt_to_meas(const exi_pvt_t *p, uint16_t *val, int8_t *factor)
{
    *val = p->value;
    *factor = (int8_t)(p->mult + 3);
}

/* Read a 1-bit inter-field event-code gate; it MUST be 0, else return the grammar's error code
 * (the stock gates shunt to -110/-133/-500 depending on position; analyze103 gate table). */
static int rd_gate(exi_stream_t *s, int err)
{
    uint32_t g;
    int r = exi_read_bits(s, 1, &g);
    if (r) return r;
    return g ? err : EXI_OK;
}

/* DC_EVSEStatus 0x0806259E — RESOLVED merged grammar (analyze103), NO DIN/ISO mode flag.
 * Wire order: E0(2 presence) [G1 ISO(2) G2] G3 G4 CODE(4) G5 G6 G7 DELAY(u32) G8 G9 G10 NOTIF(2)
 * G11 G12. E0: 0=present, 1=absent, >=2=-110. NotificationMaxDelay is a MANDATORY u32 (varlen
 * 0x08093432), present in DIN. 22 fixed bits + one u32 when isolation present; 12 one-bit gates
 * all 0. Out: isolation@status, present flag, status_code, notification_max_delay, notification.
 * Gate error codes per position: G1/G4/G7/G10=-133, G2/G5/G8/G11=-500, G3/G6/G9/G12=-110. */
int din_dc_evse_status_decode(exi_stream_t *s, din_dc_evse_status_t *out)
{
    out->isolation_present = 0;
    out->isolation_status = 0;
    out->notification = 0;
    out->status_code = 0;
    out->notification_max_delay = 0;

    uint32_t e0;
    int r = exi_read_bits(s, 2, &e0);          /* E0 isolation presence (2-bit) */
    if (r) return r;
    if (e0 >= 2u) return EXI_ERR_EMPTY;        /* >=2 -> -110 */
    if (e0 == 0u) {                            /* present: G1 ISO G2 */
        r = rd_gate(s, EXI_ERR_GATE);          /* G1 (-133) */
        if (r) return r;
        uint32_t iso;
        r = exi_read_bits(s, 2, &iso);
        if (r) return r;
        out->isolation_status = (uint8_t)iso;
        out->isolation_present = 1;
        r = rd_gate(s, EXI_ERR_GRAMMAR);       /* G2 (-500) */
        if (r) return r;
    }
    /* absent (E0==1) skips G1/ISO/G2; the rest is identical (analyze103 gate table). */
    r = rd_gate(s, EXI_ERR_EMPTY);             /* G3 (-110) */
    if (r) return r;
    r = rd_gate(s, EXI_ERR_GATE);              /* G4 (-133) */
    if (r) return r;
    uint32_t code;
    r = exi_read_bits(s, 4, &code);            /* EVSEStatusCode (4-bit) */
    if (r) return r;
    out->status_code = (uint8_t)code;
    r = rd_gate(s, EXI_ERR_GRAMMAR);           /* G5 (-500) */
    if (r) return r;
    r = rd_gate(s, EXI_ERR_EMPTY);             /* G6 (-110) */
    if (r) return r;
    r = rd_gate(s, EXI_ERR_GATE);              /* G7 (-133) */
    if (r) return r;
    r = exi_read_u32(s, &out->notification_max_delay);  /* NotificationMaxDelay u32 MANDATORY */
    if (r) return r;
    r = rd_gate(s, EXI_ERR_GRAMMAR);           /* G8 (-500) */
    if (r) return r;
    r = rd_gate(s, EXI_ERR_EMPTY);             /* G9 (-110) */
    if (r) return r;
    r = rd_gate(s, EXI_ERR_GATE);              /* G10 (-133) */
    if (r) return r;
    uint32_t notif;
    r = exi_read_bits(s, 2, &notif);           /* EVSENotification (2-bit) */
    if (r) return r;
    out->notification = (uint8_t)notif;
    r = rd_gate(s, EXI_ERR_GRAMMAR);           /* G11 (-500) */
    if (r) return r;
    return rd_gate(s, EXI_ERR_EMPTY);          /* G12 (-110); ==0 -> OK */
}

/* CurrentDemandRes 0x0806471E (ev0x12) — 10-field wire order (E §3, COMPLETE). Mandatory fields
 * byte-exact; the optional max-limit choice chain (state 0x23 readBits3 / 0x24-0x25 readBits2) is
 * RESOLVED by analyze106: a nested optional-element choice (Current->Voltage->Power order), NOT
 * per-field presence bits. Present flags + the power limit are stored in din_meas_t. */
int din_cd_res_decode_exi(const uint8_t *body, uint16_t len, din_meas_t *m, uint8_t *response_code)
{
    exi_stream_t s;
    exi_decode_init(&s, body, len);
    uint32_t rc;
    int r = exi_read_bits(&s, 5, &rc);          /* 1 ResponseCode (5-bit enum) */
    if (r) return r;
    *response_code = (uint8_t)rc;
    din_dc_evse_status_t st;
    r = din_dc_evse_status_decode(&s, &st);     /* 2 DC_EVSEStatus */
    if (r) return r;
    exi_pvt_t p;
    r = exi_read_pvt(&s, &p);                   /* 3 EVSEPresentVoltage */
    if (r) return r;
    pvt_to_meas(&p, &m->evse_present_voltage, &m->evse_present_voltage_f);
    r = exi_read_pvt(&s, &p);                   /* 4 EVSEPresentCurrent */
    if (r) return r;
    pvt_to_meas(&p, &m->evse_present_current, &m->evse_present_current_f);
    r = exi_read_bool(&s, &m->current_limit_achieved);   /* 5 */
    if (r) return r;
    r = exi_read_bool(&s, &m->voltage_limit_achieved);   /* 6 */
    if (r) return r;
    r = exi_read_bool(&s, &m->power_limit_achieved);     /* 7 */
    if (r) return r;
    /* Optional max-limit choice chain (analyze106, ev12 states 0x23/0x24/0x25). A NESTED choice
     * selects which of the remaining optional EVSEMaximum{Current,Voltage,Power}Limit PVTs comes
     * next (fixed order Current->Voltage->Power) or terminates — NOT per-field 1-bit presence:
     *   state 0x23 readBits(3): 0=CurrentLimit->0x24, 1=VoltageLimit->0x25, 2=PowerLimit->end,
     *                           3=end (>=4 -> grammar error)
     *   state 0x24 readBits(2): 0=VoltageLimit->0x25, 1=PowerLimit->end, 2=end (>=3 -> error)
     *   state 0x25 readBits(2): 0=PowerLimit->end, 1=end (>=2 -> error)
     * Each present field sets its flag (stock struct +0x34/+0x40/+0x4c = 1). */
    m->evse_max_current_present = 0;
    m->evse_max_voltage_present = 0;
    m->evse_max_power_present = 0;
    uint32_t ch;
    r = exi_read_bits(&s, 3, &ch);              /* state 0x23: 3-bit choice */
    if (r) return r;
    if (ch > 3u) return EXI_ERR_EVENT;
    int sel = (int)ch;                           /* 0=Current, 1=Voltage, 2=Power, 3=end */
    while (sel < 3) {
        exi_pvt_t lp;
        if (sel == 0) {                          /* EVSEMaximumCurrentLimit PVT @+0x2c */
            r = exi_read_pvt(&s, &lp);
            if (r) return r;
            pvt_to_meas(&lp, &m->evse_max_current, &m->evse_max_current_f);
            m->evse_max_current_present = 1;
            r = exi_read_bits(&s, 2, &ch);       /* state 0x24: 0=Voltage, 1=Power, 2=end */
            if (r) return r;
            if (ch > 2u) return EXI_ERR_EVENT;
            sel = (ch == 0u) ? 1 : (ch == 1u) ? 2 : 3;
        } else if (sel == 1) {                   /* EVSEMaximumVoltageLimit PVT @+0x38 */
            r = exi_read_pvt(&s, &lp);
            if (r) return r;
            pvt_to_meas(&lp, &m->evse_max_voltage, &m->evse_max_voltage_f);
            m->evse_max_voltage_present = 1;
            r = exi_read_bits(&s, 2, &ch);       /* state 0x25: 0=Power, 1=end */
            if (r) return r;
            if (ch > 1u) return EXI_ERR_EVENT;
            sel = (ch == 0u) ? 2 : 3;
        } else {                                 /* sel==2: EVSEMaximumPowerLimit PVT @+0x44 */
            r = exi_read_pvt(&s, &lp);
            if (r) return r;
            pvt_to_meas(&lp, &m->evse_max_power, &m->evse_max_power_f);
            m->evse_max_power_present = 1;
            sel = 3;                             /* -> state 4 (terminal EE gate) */
        }
    }
    return EXI_OK;
}

/* CableCheckRes 0x08066C5C (ev0x05): ResponseCode(5) + DC_EVSEStatus + EVSEProcessingState(1). */
int din_cablecheck_res_decode_exi(const uint8_t *body, uint16_t len, uint8_t *response_code,
                                  uint8_t *processing, din_dc_evse_status_t *status)
{
    exi_stream_t s;
    exi_decode_init(&s, body, len);
    uint32_t rc;
    int r = exi_read_bits(&s, 5, &rc);
    if (r) return r;
    *response_code = (uint8_t)rc;
    r = din_dc_evse_status_decode(&s, status);
    if (r) return r;
    uint32_t proc;
    r = exi_read_bits(&s, 1, &proc);            /* EVSEProcessingState: 0 finished / 1 ongoing */
    if (r) return r;
    *processing = (uint8_t)proc;
    return EXI_OK;
}

/* PreChargeRes 0x08063A8A (ev0x30): ResponseCode(5) + DC_EVSEStatus + EVSEPresentVoltage PVT. */
int din_precharge_res_decode_exi(const uint8_t *body, uint16_t len, din_meas_t *m,
                                 uint8_t *response_code, din_dc_evse_status_t *status)
{
    exi_stream_t s;
    exi_decode_init(&s, body, len);
    uint32_t rc;
    int r = exi_read_bits(&s, 5, &rc);
    if (r) return r;
    *response_code = (uint8_t)rc;
    r = din_dc_evse_status_decode(&s, status);
    if (r) return r;
    exi_pvt_t p;
    r = exi_read_pvt(&s, &p);
    if (r) return r;
    pvt_to_meas(&p, &m->evse_present_voltage, &m->evse_present_voltage_f);
    return EXI_OK;
}

/* SessionStopRes 0x08063C04 (ev0x1e): EMPTY (1-bit choice 0=empty/valid, 1=err -110). */
int din_sessionstop_res_decode_exi(const uint8_t *body, uint16_t len)
{
    exi_stream_t s;
    exi_decode_init(&s, body, len);
    uint32_t choice;
    int r = exi_read_bits(&s, 1, &choice);
    if (r) return r;
    return choice ? EXI_ERR_EMPTY : EXI_OK;
}

/* ---- B2 DIN document message codec (analyze101/102/103) ---- */

/* PVT from a meas value + stored factor (mult = factor-3). The PVT wire mechanism is byte-exact
 * (analyze106, encoder 0x0806A3AC): gate, gate, Multiplier(3-bit = mult+3), gate, Unit choice(2)
 * [0=present -> gate, Unit(4-bit @struct+1), gate | 1=absent], gate, Value(signed), gate, EE gate.
 * The Unit is a caller-set 4-bit schema enum (DIN unitType: A=1 / V=3, schema-derived); the
 * replica emits it present (unit_present=1) for every measurement PVT. */
static void meas_to_pvt(const exi_pvt_t *unused, uint16_t val, int8_t factor, uint8_t unit,
                        exi_pvt_t *p)
{
    (void)unused;
    p->mult = (int8_t)(factor - 3);
    p->unit = unit;
    p->unit_present = 1;
    p->value = val;
}

/* DC_EVStatus ev17 0x0806A936 encoder — recovered DEFAULT grammar (builder presence flags
 * [body+8]/[body+0x10]=0; EVReady[body+0]=1; [body+0x11]=0; EVRESSSOC[body+0x12]=soc). Trace:
 *   state 0xc1: gate0 gate0 EVReady(bool) gate0
 *   state 0xc2: choice(2,2) gate0 4-bit([body+0x11]=0) gate0
 *   state 0xc5: gate0 gate0 EVRESSSOC(7-bit, [body+0x12]) gate0
 *   state 4   : terminal gate0
 * 23 bits total. For EVReady=1/soc=0x46 the wire is 0x28 0x02 0x30. */
int din_dc_ev_status_encode(exi_stream_t *s, uint8_t ev_ready, uint8_t soc)
{
    int r = exi_write_gate(s);                 /* 0xc1 g1 */
    if (r) return r;
    r = exi_write_gate(s);                     /* 0xc1 g2 */
    if (r) return r;
    r = exi_write_bool(s, ev_ready);           /* EVReady (0x08093982 bool encoder) */
    if (r) return r;
    r = exi_write_gate(s);                     /* 0xc1 g3 */
    if (r) return r;
    r = exi_write_bits(s, 2, 2);               /* 0xc2 choice 2 (EVErrorCode/EVRESSSOC default) */
    if (r) return r;
    r = exi_write_gate(s);                     /* 0xc2 g */
    if (r) return r;
    r = exi_write_bits(s, 4, 0);               /* 4-bit [body+0x11] = 0 */
    if (r) return r;
    r = exi_write_gate(s);                     /* 0xc2 g */
    if (r) return r;
    r = exi_write_gate(s);                     /* 0xc5 g1 */
    if (r) return r;
    r = exi_write_gate(s);                     /* 0xc5 g2 */
    if (r) return r;
    r = exi_write_bits(s, 7, soc & 0x7Fu);     /* EVRESSSOC 7-bit percent */
    if (r) return r;
    r = exi_write_gate(s);                     /* 0xc5 g3 */
    if (r) return r;
    return exi_write_gate(s);                  /* state 4 terminal gate */
}

/* Common Req document framing: reserve 8-byte V2GTP + leading 0x80 + root 0x4D + DIN header +
 * 6-bit choice. Leaves the stream at the body start. */
static int req_doc_begin(exi_stream_t *s, uint8_t *buf, uint16_t cap, uint8_t choice,
                         const uint8_t *sid, uint16_t sid_len)
{
    exi_encode_init(s, buf, cap, EXI_V2GTP_HDR_LEN);
    int r = exi_encode_header(s, EXI_DIN_ROOT);
    if (r) return r;
    return exi_din_encode_doc_start(s, choice, sid, sid_len);
}
static int req_doc_end(exi_stream_t *s)
{
    int r = exi_din_encode_doc_end(s);         /* EE gate */
    if (r) return r;
    return (int)exi_encode_finish(s);
}

/* SessionSetupReq ev40 0x0806ABEA (choice 0x1D): EVCCID hexBinary octet string (varlen-len +
 * octets; stock EVCCID = 6 bytes from the unit MAC getter 0x080896C0). Prologue CONFIRMED by
 * analyze106: gate, gate, EVCCID(varlen-len + octets), gate, gate(EE) — four 1-bit gates. */
int din_sessionsetup_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                                const uint8_t *evccid, uint16_t evccid_len)
{
    exi_stream_t s;
    int r = req_doc_begin(&s, buf, cap, DIN_REQ_SESSIONSETUP, sid, sid_len);
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    r = exi_write_octet(&s, evccid, evccid_len);   /* EVCCID (0x0809392A + 0x08093B5E) */
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    return req_doc_end(&s);
}

/* ServiceDiscoveryReq ev3c 0x0806B06A (choice 0x19): optional ServiceScope + ServiceCategory,
 * both absent in the DIN default (gates [body+0x24]/bit16 clear). Emits the absent choice. */
int din_servicediscovery_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len)
{
    exi_stream_t s;
    int r = req_doc_begin(&s, buf, cap, DIN_REQ_SERVICEDISCOVERY, sid, sid_len);
    if (r) return r;
    r = exi_write_gate(&s);                    /* scope gate (absent) */
    if (r) return r;
    r = exi_write_bits(&s, 1, 0);              /* ServiceCategory bit16 gate (absent) */
    if (r) return r;
    return req_doc_end(&s);
}

/* CableCheckReq ev04 0x0806D698 (choice 0x01) / WeldingReq ev4e 0x0806AA92 (choice 0x21):
 * gate + DC_EVStatus ev17 + gate (Group N: ev04/ev4e bl ev17; ev4e probe gate+ev17+gate). */
static int dc_evstatus_req_encode(uint8_t *buf, uint16_t cap, uint8_t choice,
                                  const uint8_t *sid, uint16_t sid_len, uint8_t ev_ready, uint8_t soc)
{
    exi_stream_t s;
    int r = req_doc_begin(&s, buf, cap, choice, sid, sid_len);
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    r = din_dc_ev_status_encode(&s, ev_ready, soc);
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    return req_doc_end(&s);
}
int din_cablecheck_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                              uint8_t ev_ready, uint8_t soc)
{
    return dc_evstatus_req_encode(buf, cap, DIN_REQ_CABLECHECK, sid, sid_len, ev_ready, soc);
}
int din_welding_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                           uint8_t ev_ready, uint8_t soc)
{
    return dc_evstatus_req_encode(buf, cap, DIN_REQ_WELDING, sid, sid_len, ev_ready, soc);
}

/* PreChargeReq ev2f 0x0806B4DE (choice 0x15): DC_EVStatus + EVTargetCurrent PVT@0x14 +
 * EVTargetVoltage PVT@0x1C (Group O). Inter-field gates RESOLVED by analyze106: FOUR 1-bit gates
 * bracket the body — gate, DC_EVStatus, gate, EVTargetCurrent, gate, EVTargetVoltage, gate(EE)
 * (the gate between DC_EVStatus and EVTargetCurrent was previously missing). */
int din_precharge_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                             const din_meas_t *m, uint8_t ev_ready, uint8_t soc)
{
    exi_stream_t s;
    int r = req_doc_begin(&s, buf, cap, DIN_REQ_PRECHARGE, sid, sid_len);
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    r = din_dc_ev_status_encode(&s, ev_ready, soc);
    if (r) return r;
    r = exi_write_gate(&s);                    /* gate between DC_EVStatus and EVTargetCurrent */
    if (r) return r;
    exi_pvt_t p;
    meas_to_pvt(0, m->ev_target_current, m->ev_target_current_f, 1, &p);
    r = exi_write_pvt(&s, &p);                 /* EVTargetCurrent */
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    meas_to_pvt(0, m->ev_target_voltage, m->ev_target_voltage_f, 3, &p);
    r = exi_write_pvt(&s, &p);                 /* EVTargetVoltage */
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    return req_doc_end(&s);
}

/* PowerDeliveryReq ev2d 0x0806B814 (choice 0x13): ChargeProgress (bool encoder 0x08093982:
 * Start=0/Stop=1) + optional ChargingSessionDetails param (absent, gate [body+0xcc] clear). */
int din_powerdelivery_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                                 uint8_t charge_progress)
{
    exi_stream_t s;
    int r = req_doc_begin(&s, buf, cap, DIN_REQ_POWERDELIVERY, sid, sid_len);
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    r = exi_write_bool(&s, charge_progress);   /* ChargeProgress 0=Start 1=Stop */
    if (r) return r;
    r = exi_write_gate(&s);                    /* optional-param gate (absent) */
    if (r) return r;
    return req_doc_end(&s);
}

/* SessionStopReq ev42 0x0806AB0E (choice 0x1F): EMPTY body — writeBits(1,0) (Group J). */
int din_sessionstop_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len)
{
    exi_stream_t s;
    int r = req_doc_begin(&s, buf, cap, DIN_REQ_SESSIONSTOP, sid, sid_len);
    if (r) return r;
    r = exi_write_bits(&s, 1, 0);              /* empty choice 0 */
    if (r) return r;
    return req_doc_end(&s);
}

/* ChargeParameterDiscoveryReq ev0b 0x0806CEF0 (choice 0x07): prologue RESOLVED by analyze106 —
 * gate, gate, EnergyTransferMode(3-bit), gate, AC/DC choice(2). DIN takes choice 1 ->
 * DC_EVChargeParameter ev13 0x0806CC3A (choice 0 = AC param 0x0806CE20, choice 2 = 0x0806CC32).
 * The ETM is a 3-bit caller-set enum (DC=3, schema-derived); the ev13 DC param body below emits
 * DC_EVStatus + the EVSE-requested max limits from meas (a documented simplification of the full
 * ev13 optional-field chain: maxPower is a 2-bit choice, not a gated-absent bit). */
int din_cpd_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                       const din_meas_t *m, uint8_t ev_ready, uint8_t soc)
{
    exi_stream_t s;
    int r = req_doc_begin(&s, buf, cap, DIN_REQ_CPD, sid, sid_len);
    if (r) return r;
    r = exi_write_gate(&s);                    /* ev0b gate A */
    if (r) return r;
    r = exi_write_gate(&s);                    /* ev0b gate B */
    if (r) return r;
    r = exi_write_bits(&s, 3, 3);              /* EnergyTransferMode = DC (3-bit, caller-set) */
    if (r) return r;
    r = exi_write_gate(&s);                    /* ev0b gate C (before the AC/DC choice) */
    if (r) return r;
    r = exi_write_bits(&s, 2, 1);              /* AC/DC choice 1 = DC_EVChargeParameter ev13 */
    if (r) return r;
    r = exi_write_gate(&s);                    /* ev13 state 0x41 gate */
    if (r) return r;
    r = din_dc_ev_status_encode(&s, ev_ready, soc);   /* DC_EVChargeParameter.DC_EVStatus */
    if (r) return r;
    exi_pvt_t p;
    meas_to_pvt(0, m->evse_max_current, m->evse_max_current_f, 1, &p);
    r = exi_write_pvt(&s, &p);                 /* EVMaximumCurrentLimit */
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    r = exi_write_bits(&s, 2, 1);              /* EVMaximumPowerLimit optional absent */
    if (r) return r;
    meas_to_pvt(0, m->evse_max_voltage, m->evse_max_voltage_f, 3, &p);
    r = exi_write_pvt(&s, &p);                 /* EVMaximumVoltageLimit */
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    return req_doc_end(&s);
}

/* CurrentDemandReq ev11 0x0806BDDC (choice 0x0D) — full field list (analyze101 Group I):
 * DC_EVStatus@0x00 + EVTargetCurrent PVT@0x14 + opt EVMaximumPowerLimit@0x1C (gate 0x24) /
 * EVMaximumCurrentLimit@0x28 (gate 0x30) / EVMaximumVoltageLimit@0x34 (gate 0x3C) +
 * BulkChargingComplete@0x40 (gate 0x44) + ChargingComplete@0x48 + opt RemainingTimeToFullSOC@0x4C
 * (gate 0x54) / RemainingTimeToBulkSOC@0x58 (gate 0x60) + EVTargetVoltage PVT@0x64. The optional
 * limits are gated-absent in the inert default; the recovered actuation fields (targets, bulk/
 * charging complete) are emitted byte-faithfully (offsets corrected by analyze101). */
int din_cd_req_encode_exi(din_meas_t *m, uint8_t *buf, uint16_t cap,
                          const uint8_t *sid, uint16_t sid_len)
{
    exi_stream_t s;
    int r = req_doc_begin(&s, buf, cap, DIN_REQ_CURRENTDEMAND, sid, sid_len);
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    r = din_dc_ev_status_encode(&s, m->ev_ready, 70);   /* DC_EVStatus @0x00 */
    if (r) return r;
    exi_pvt_t p;
    meas_to_pvt(0, m->ev_target_current, m->ev_target_current_f, 1, &p);
    r = exi_write_pvt(&s, &p);                 /* EVTargetCurrent PVT @0x14 */
    if (r) return r;
    r = exi_write_gate(&s);                    /* gate 0x24 (EVMaximumPowerLimit absent) */
    if (r) return r;
    r = exi_write_bits(&s, 2, 1);              /* opt EVMaximumPowerLimit absent */
    if (r) return r;
    r = exi_write_gate(&s);                    /* gate 0x30 (EVMaximumCurrentLimit absent) */
    if (r) return r;
    r = exi_write_bits(&s, 2, 1);              /* opt EVMaximumCurrentLimit absent */
    if (r) return r;
    r = exi_write_gate(&s);                    /* gate 0x3C (EVMaximumVoltageLimit absent) */
    if (r) return r;
    r = exi_write_bits(&s, 2, 1);              /* opt EVMaximumVoltageLimit absent */
    if (r) return r;
    r = exi_write_gate(&s);                    /* gate 0x44 */
    if (r) return r;
    r = exi_write_bool(&s, m->bulk_charging_complete);   /* BulkChargingComplete @0x40 */
    if (r) return r;
    r = exi_write_bool(&s, m->charging_complete);        /* ChargingComplete @0x48 */
    if (r) return r;
    r = exi_write_gate(&s);                    /* gate 0x54 (RemainingTimeToFullSOC absent) */
    if (r) return r;
    r = exi_write_bits(&s, 2, 1);
    if (r) return r;
    r = exi_write_gate(&s);                    /* gate 0x60 (RemainingTimeToBulkSOC absent) */
    if (r) return r;
    r = exi_write_bits(&s, 2, 1);
    if (r) return r;
    meas_to_pvt(0, m->ev_target_voltage, m->ev_target_voltage_f, 3, &p);
    r = exi_write_pvt(&s, &p);                 /* EVTargetVoltage PVT @0x64 */
    if (r) return r;
    r = exi_write_gate(&s);
    if (r) return r;
    m->first_demand_sent = 1u;
    return req_doc_end(&s);
}

/* CPD Res DC_EVSEChargeParameter ev15 0x080650D2 decoder (analyze102). DC_EVSEStatus + 8 PVTs
 * (maxCurrent req, maxPower opt, maxVoltage req, minCurrent req, minVoltage req, opt, req, energy
 * opt). Optional fields: 2-bit choice (0=present+flag, 1=skip). */
int din_dc_charge_param_decode(exi_stream_t *s, din_dc_charge_param_t *out)
{
    int r = din_dc_evse_status_decode(s, &out->status);   /* DC_EVSEStatus @+0 */
    if (r) return r;
    r = exi_read_pvt(s, &out->max_current);               /* @+0xC required */
    if (r) return r;
    uint32_t choice;
    r = exi_read_bits(s, 2, &choice);                     /* maxPower optional @+0x14 */
    if (r) return r;
    out->max_power_present = (choice == 0u);
    if (choice == 0u) { r = exi_read_pvt(s, &out->max_power); if (r) return r; }
    r = exi_read_pvt(s, &out->max_voltage);               /* @+0x20 required */
    if (r) return r;
    r = exi_read_pvt(s, &out->min_current);               /* @+0x28 required */
    if (r) return r;
    r = exi_read_pvt(s, &out->min_voltage);               /* @+0x30 required */
    if (r) return r;
    r = exi_read_bits(s, 2, &choice);                     /* opt @+0x38 */
    if (r) return r;
    out->opt_limit_present = (choice == 0u);
    if (choice == 0u) { r = exi_read_pvt(s, &out->opt_limit); if (r) return r; }
    r = exi_read_pvt(s, &out->peak_current);              /* @+0x44 required */
    if (r) return r;
    r = exi_read_bits(s, 2, &choice);                     /* energy optional @+0x4C */
    if (r) return r;
    out->energy_present = (choice == 0u);
    if (choice == 0u) { r = exi_read_pvt(s, &out->energy); if (r) return r; }
    return EXI_OK;
}

/* SessionSetupRes ev41 0x08062B1E (subev 0x1E): gate gate RC(5) gate EVSEID (varlen-len + octets,
 * clamp 32) + optional EVSETimeStamp (2-bit choice 0=present -> 8-byte fixed 0x08093550). */
int din_sessionsetup_res_decode_exi(const uint8_t *body, uint16_t len, uint8_t *response_code,
                                    uint8_t *evseid, uint16_t *evseid_len)
{
    exi_stream_t s;
    exi_decode_init(&s, body, len);
    int r = exi_read_gate(&s, EXI_ERR_GATE);              /* lead gate1 */
    if (r) return r;
    r = exi_read_gate(&s, EXI_ERR_GATE);                  /* lead gate2 */
    if (r) return r;
    uint32_t rc;
    r = exi_read_bits(&s, 5, &rc);                        /* ResponseCode */
    if (r) return r;
    *response_code = (uint8_t)rc;
    r = exi_read_gate(&s, EXI_ERR_GATE);                  /* post-RC gate */
    if (r) return r;
    r = exi_read_octet(&s, evseid, 32, evseid_len);       /* EVSEID varlen-len + octets (cap 32) */
    if (r) return r;
    uint32_t choice;
    r = exi_read_bits(&s, 2, &choice);                    /* EVSETimeStamp optional choice */
    if (r) return r;
    if (choice == 0u) {                                   /* present: 8-byte fixed timestamp */
        for (int i = 0; i < 8; i++) {
            uint32_t b; r = exi_read_bits(&s, 8, &b); if (r) return r;
        }
    }
    return EXI_OK;
}

/* ServiceDiscoveryRes ev3d 0x08063370 (subev 0x1A): list grammar RESOLVED by analyze106 —
 *   state 0x8c: gate, gate, RC(5), gate
 *   state 0x8d: gate, ChargeServiceList (0x0806327A, struct+2; count<=5)
 *   state 0x8e: gate, ServiceList ev39 (0x0806316A, struct+0xc)
 *   state 0x8f: choice(2) 0 = optional EnergyTransferModeList (0x0806A192, struct+0x64, count<=8,
 *               present flag struct+0x308), 1 = absent -> state 4 terminal gate.
 * The replica extracts RC for session advancement (3->6); the lists are not consumed (the EVCC
 * does not act on them) and the raw body is preserved by the application writer (memcpy
 * meas+0x37e0). Returns OK after RC. Full list consumption is deferred (unused by the session). */
int din_servicediscovery_res_decode_exi(const uint8_t *body, uint16_t len, uint8_t *response_code)
{
    exi_stream_t s;
    exi_decode_init(&s, body, len);
    uint32_t rc;
    int r = exi_read_bits(&s, 5, &rc);                    /* ResponseCode (first field) */
    if (r) return r;
    *response_code = (uint8_t)rc;
    return EXI_OK;
}

/* CPDRes ev0c 0x08065BFC (subev 0x08): RC(5) + processing flag(1)@body+1 + sched-choice(2)
 * + AC/DC-param choice(2). RESOLVED by analyze106: state 0x74 sched-choice 0 = AC schedule ev35
 * (0x08065B62), 1 = DIN empty schedule (0x08065368); state 0x75 AC/DC choice 1 = DCparam ev15
 * (0x080650D2), 0 = 0x08065296, 2 = 0x080650AC. DIN takes choice 1 on both. The handler case6
 * branches on body+1==1 (processing ongoing). */
int din_cpd_res_decode_exi(const uint8_t *body, uint16_t len, uint8_t *response_code,
                           uint8_t *processing, din_dc_charge_param_t *param)
{
    exi_stream_t s;
    exi_decode_init(&s, body, len);
    uint32_t rc;
    int r = exi_read_bits(&s, 5, &rc);                    /* ResponseCode */
    if (r) return r;
    *response_code = (uint8_t)rc;
    uint32_t proc;
    r = exi_read_bits(&s, 1, &proc);                      /* state0x73 processing flag @body+1 */
    if (r) return r;
    *processing = (uint8_t)proc;
    uint32_t choice;
    r = exi_read_bits(&s, 2, &choice);                    /* state0x74 sched choice (DIN=1 empty) */
    if (r) return r;
    if (choice == 0u) {                                   /* AC sched ev35 0x08065B62 (DIN takes 1) */
        return EXI_ERR_EVENT;
    }
    r = exi_read_bits(&s, 2, &choice);                    /* state0x75 AC/DC param choice */
    if (r) return r;
    if (choice != 1u) {                                   /* DIN=1 -> DCparam ev15 */
        return EXI_ERR_EVENT;
    }
    return din_dc_charge_param_decode(&s, param);
}

/* PowerDeliveryRes ev2e 0x08063DBA (subev 0x14): gate gate RC(5) gate EVSEStatus-choice(2);
 * DIN choice 1 -> DC_EVSEStatus@+0x20 (choice 0 AC, choice 2 empty). LINEAR. */
int din_powerdelivery_res_decode_exi(const uint8_t *body, uint16_t len, uint8_t *response_code,
                                     din_dc_evse_status_t *status)
{
    exi_stream_t s;
    exi_decode_init(&s, body, len);
    int r = exi_read_gate(&s, EXI_ERR_GATE);              /* lead gate1 */
    if (r) return r;
    r = exi_read_gate(&s, EXI_ERR_GATE);                  /* lead gate2 */
    if (r) return r;
    uint32_t rc;
    r = exi_read_bits(&s, 5, &rc);                        /* ResponseCode */
    if (r) return r;
    *response_code = (uint8_t)rc;
    r = exi_read_gate(&s, EXI_ERR_GATE);                  /* post-RC gate */
    if (r) return r;
    uint32_t choice;
    r = exi_read_bits(&s, 2, &choice);                    /* EVSEStatus choice */
    if (r) return r;
    if (choice == 1u) {                                   /* DIN DC_EVSEStatus */
        r = din_dc_evse_status_decode(&s, status);
        if (r) return r;
    }
    r = exi_read_gate(&s, EXI_ERR_GATE);                  /* trailing gate */
    if (r) return r;
    return EXI_OK;
}

/* WeldingDetectionRes ev4f 0x08062754 (subev 0x22): gate gate RC(5) gate DC_EVSEStatus@+4 gate
 * EVSEPresentVoltage PVT@+0x10 -> meas.evse_present_voltage (+factor) gate. */
int din_welding_res_decode_exi(const uint8_t *body, uint16_t len, din_meas_t *m,
                               uint8_t *response_code, din_dc_evse_status_t *status)
{
    exi_stream_t s;
    exi_decode_init(&s, body, len);
    int r = exi_read_gate(&s, EXI_ERR_GATE);              /* lead gate1 */
    if (r) return r;
    r = exi_read_gate(&s, EXI_ERR_GATE);                  /* lead gate2 */
    if (r) return r;
    uint32_t rc;
    r = exi_read_bits(&s, 5, &rc);                        /* ResponseCode */
    if (r) return r;
    *response_code = (uint8_t)rc;
    r = exi_read_gate(&s, EXI_ERR_GATE);                  /* post-RC gate */
    if (r) return r;
    r = exi_read_gate(&s, EXI_ERR_GATE);                  /* state0xe gate */
    if (r) return r;
    r = din_dc_evse_status_decode(&s, status);            /* DC_EVSEStatus @+4 */
    if (r) return r;
    r = exi_read_gate(&s, EXI_ERR_GATE);                  /* state0xf gate */
    if (r) return r;
    exi_pvt_t p;
    r = exi_read_pvt(&s, &p);                             /* EVSEPresentVoltage PVT @+0x10 */
    if (r) return r;
    pvt_to_meas(&p, &m->evse_present_voltage, &m->evse_present_voltage_f);
    r = exi_read_gate(&s, EXI_ERR_GATE);                  /* trailing gate */
    if (r) return r;
    return EXI_OK;
}