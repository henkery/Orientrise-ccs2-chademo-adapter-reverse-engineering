/* cp.c — CCS2 CP/PP analog signaling (REPORT §5.9, Agent B / analyze92).
 * Faithful INERT replica of the C013 CP/PP monitor logic. Communication/link signaling only —
 * BCB (PD11) drive is recorded, not executed (gated). Pure helpers host-tested (test_cp.c).
 */
#include "cp.h"

static cp_t cp;
static uint8_t pp_state;     /* 0 unplugged, 1 plugged (stock 0x200008B4) */
static uint8_t pp_counter;   /* debounce counter (stock 0x200008B5)       */

uint16_t cp_ad_pp(uint16_t raw)
{
    /* 0x08088850: muls raw*0xCE4(3300) ; udiv /0xFFF0(65520). */
    return (uint16_t)(((uint32_t)raw * 3300u) / 65520u);
}

uint16_t cp_ad_cpd(uint16_t raw)
{
    /* 0x08088878: muls raw*0xCE4(3300) ; udiv /0x7FF8(32760). */
    return (uint16_t)(((uint32_t)raw * 3300u) / 32760u);
}

uint16_t cp_ad_cp(uint16_t raw)
{
    /* 0x08088864: muls raw*0x19C8(6600) ; udiv /0x7FF8(32760). */
    return (uint16_t)(((uint32_t)raw * 6600u) / 32760u);
}

uint8_t cp_state_char(uint16_t duty, uint8_t pd11, uint8_t fault)
{
    /* 0x08052914: fault!=0 -> 'F' ; duty==0 -> 'E' ; PD11!=0 -> 'C' ; else 'B'.
     * (C013 fault fn 0x08088B9A is stubbed movs#0, so 'F' never occurs in practice.) */
    if (fault != 0) return CP_STATE_F;
    if (duty == 0)  return CP_STATE_E;
    if (pd11 != 0)  return CP_STATE_C;
    return CP_STATE_B;
}

uint8_t cp_duty5(uint16_t duty)
{
    /* 0x08052804: r1=duty-30 ; cmp r1,#40 ; if duty in [30,70] -> '5' else raw duty (low byte). */
    if (duty >= CP_DUTY5_LO && duty <= CP_DUTY5_HI) return CP_DIGITAL_5;
    return (uint8_t)duty;
}

uint8_t cp_pp_update(uint16_t pp_mv, uint8_t *state, uint8_t *counter)
{
    /* 0x080527B0: hysteresis + 4-sample debounce.
     * plugged && mV>=2296 -> counter++, >=4 -> unplugged ; plugged && mV<2296 -> counter=0.
     * unplugged && mV>2146 -> counter=0 ; unplugged && mV<=2146 -> counter++, >=4 -> plugged. */
    uint8_t s = *state;
    uint8_t c = *counter;
    if (s) {
        if (pp_mv >= CP_PP_UNPLUG_MV) {
            c++;
            if (c >= CP_PP_DEBOUNCE) { s = 0; c = 0; }
        } else {
            c = 0;
        }
    } else {
        if (pp_mv > CP_PP_PLUG_MV) {
            c = 0;
        } else {
            c++;
            if (c >= CP_PP_DEBOUNCE) { s = 1; c = 0; }
        }
    }
    *state = s;
    *counter = c;
    return s;
}

void cp_init(void)
{
    cp.pp_mv = 0; cp.cpd_mv = 0; cp.cp_duty = 0; cp.cp_freq = 0;
    cp.cp_state = CP_STATE_E; cp.digital_5 = 0; cp.plug_in = 0;
    cp.d_link = 0; cp.bcb_action = CP_STATE_B;
    pp_state = 0; pp_counter = 0;
}

void cp_step(uint16_t pp_raw, uint16_t cpd_raw, uint16_t duty, uint16_t freq,
             uint8_t pd11, uint8_t d_link)
{
    cp.pp_mv   = cp_ad_pp(pp_raw);
    cp.cpd_mv  = cp_ad_cpd(cpd_raw);
    cp.cp_duty = duty;
    cp.cp_freq = freq;
    cp.cp_state = cp_state_char(duty, pd11, 0);   /* fault stubbed (C013) */
    cp.digital_5 = (cp_duty5(duty) == CP_DIGITAL_5) ? 1u : 0u;
    cp.plug_in = cp_pp_update(cp.pp_mv, &pp_state, &pp_counter);
    cp.d_link = d_link;
    /* BCB intended level follows CP state ('C' engages PD11); RECORDED only — no GPIO drive. */
    cp.bcb_action = (cp.cp_state == CP_STATE_C) ? CP_STATE_C : CP_STATE_B;
}

const cp_t *cp_get(void) { return &cp; }
uint8_t cp_plug_in(void) { return cp.plug_in; }