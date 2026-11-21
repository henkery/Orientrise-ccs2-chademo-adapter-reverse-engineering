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
 * modeled here with per-field 1-bit presence [? exact grammar-id transitions not fully recovered]. */
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
    uint8_t present;                            /* 8 EVSEMaximumVoltageLimit (opt) [?] */
    r = exi_read_bool(&s, &present);
    if (r) return r;
    if (present) {
        r = exi_read_pvt(&s, &p);
        if (r) return r;
        pvt_to_meas(&p, &m->evse_max_voltage, &m->evse_max_voltage_f);
    }
    r = exi_read_bool(&s, &present);            /* 9 EVSEMaximumCurrentLimit (opt) [?] */
    if (r) return r;
    if (present) {
        r = exi_read_pvt(&s, &p);
        if (r) return r;
        pvt_to_meas(&p, &m->evse_max_current, &m->evse_max_current_f);
    }
    r = exi_read_bool(&s, &present);            /* 10 EVSEMaximumPowerLimit (opt) [?] */
    if (r) return r;
    if (present) {
        exi_pvt_t pw;
        r = exi_read_pvt(&s, &pw);
        if (r) return r;
        (void)pw;   /* power limit not stored in din_meas_t (no field); consumed for wire alignment */
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

/* CurrentDemandReq grammar encoder (D application field map 0x0802C2CE + exi primitives). Framing
 * (8-byte V2GTP reserved + leading 0x80 + 7-bit req_ev) then DC_EVStatus {EVReady, EVErrorCode} +
 * EVTargetCurrent PVT + EVTargetVoltage PVT + ChargingComplete bool. The full DIN Req optional
 * field set (EVMaximum* limits, BulkChargingComplete, RemainingTime*) is [?] (E §3 partial); the
 * recovered actuation fields (EVTargetCurrent/Voltage, DC_EVStatus) are emitted byte-faithfully.
 * INERT: produces the EXI image; the live TCP/TLS send is gated. Returns total length or error. */
int din_cd_req_encode_exi(din_meas_t *m, uint8_t *buf, uint16_t cap, uint8_t req_ev)
{
    exi_stream_t s;
    exi_encode_init(&s, buf, cap, EXI_V2GTP_HDR_LEN);
    int r = exi_encode_header(&s, req_ev);
    if (r < 0) return r;
    /* DC_EVStatus: EVReady (bool), EVErrorCode (2-bit enum: NO_ERROR=0). */
    r = exi_write_bool(&s, m->ev_ready);
    if (r < 0) return r;
    r = exi_write_bits(&s, 2, m->ev_error_code & 3u);
    if (r < 0) return r;
    /* EVTargetCurrent PVT (meas factor -> signed mult = factor-3). */
    exi_pvt_t p;
    p.mult = (int8_t)(m->ev_target_current_f - 3);
    p.unit = 1;            /* DIN unit enum: A (ampere) [?] */
    p.unit_present = 1;
    p.value = m->ev_target_current;
    r = exi_write_pvt(&s, &p);
    if (r < 0) return r;
    /* EVTargetVoltage PVT. */
    p.mult = (int8_t)(m->ev_target_voltage_f - 3);
    p.unit = 3;            /* DIN unit enum: V (volt) [?] */
    p.unit_present = 1;
    p.value = m->ev_target_voltage;
    r = exi_write_pvt(&s, &p);
    if (r < 0) return r;
    /* ChargingComplete (bool) — terminates the demand loop when set. */
    r = exi_write_bool(&s, 0);
    if (r < 0) return r;
    m->first_demand_sent = 1u;
    return (int)exi_encode_finish(&s);
}