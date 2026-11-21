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
    /* 0x0802C2CE / excerpt 0x0802C406: EVTargetCurrent meas[0x3CE0]->EXI[0x18], factor-3->[0x14];
     * EVTargetVoltage meas[0x3CE2]->EXI[0x68], factor-3->[0x64]; DC_EVStatus EVReady->[0x40],
     * EVErrorCode->[0x48], [0x44]=1. Wire factor = stored factor - 3. */
    z(exi, DIN_CDQ_TX_LEN);
    st16(exi + DIN_CDQ_EXI_TARGET_I, m->ev_target_current);
    exi[DIN_CDQ_EXI_TARGET_I_F] = (uint8_t)(m->ev_target_current_f - 3u);
    st16(exi + DIN_CDQ_EXI_TARGET_V, m->ev_target_voltage);
    exi[DIN_CDQ_EXI_TARGET_V_F] = (uint8_t)(m->ev_target_voltage_f - 3u);
    exi[DIN_CDQ_EXI_EVREADY]      = m->ev_ready;
    exi[DIN_CDQ_EXI_EVSTATUS_TAG] = 1u;
    exi[DIN_CDQ_EXI_EVERROR]      = m->ev_error_code;
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