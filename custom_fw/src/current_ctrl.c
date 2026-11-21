/* current_ctrl.c — INERT H102 output-current control law (shadow), REPORT §5.21 E.
 * Byte-exact replica of the C013 state-30 CurrentDemand block 0x08044D42–0x08044DBC
 * (analyze89). Computes the output-current setpoint + target voltage; drives NO power stage.
 */
#include "current_ctrl.h"
#include "din70121.h"

static current_ctrl_t cc;

int32_t current_ctrl_converter(int8_t code)
{
    /* 0x0804E786: cmp #7 ; blt -> power-of-10 TABLE[code] ; else movs #0xff. The sxtb is in the
     * CALLER (state-30 0x08044D4C), not here. CORRECTS analyze89's "(code<7)?code:0xFF" reading:
     * the blt path is a table lookup (ldr [0x20000808 + code*4]), pow10[code] for code in [0,6].
     * Delegates to the shared DIN PhysicalValueType scaling (din70121.c). */
    return (int32_t)din_pow10(code);
}

uint16_t current_ctrl_scale(uint16_t raw, int8_t factor)
{
    /* muls raw*pow10(factor) (low 32) ; udiv /1000 ; strh low16. real = raw*10^(factor-3). */
    return din_scale(raw, factor);
}

void current_ctrl_init(void)
{
    cc.setpoint     = 0;
    cc.setpoint_raw = 0;
    cc.cap          = 0;
    cc.target_v     = 0;
    cc.target_v_raw = 0;
}

void current_ctrl_step(const current_ctrl_inputs_t *in)
{
    /* cap = EVSE max-current scaled -> +0x1a (written unconditionally). */
    cc.cap = current_ctrl_scale(in->evse_max_raw, in->evse_max_factor);

    /* avail = EVSE present/available current scaled. */
    uint16_t avail = current_ctrl_scale(in->evse_avail_raw, in->evse_avail_factor);

    /* r0 = min(H102.ChargingCurrentRequest, avail):
     *   cmp request,avail ; bhs keep avail ; mov r0,request. */
    uint16_t req = in->current_request;
    uint16_t m = (req < avail) ? req : avail;

    /* cbz r0 -> skip the current stores when the min is 0 (keep previous setpoint). */
    if (m != 0u) {
        cc.setpoint_raw = m;   /* +0x18 uncapped */
        cc.setpoint     = m;   /* +0x16 */
        /* cap: cmp setpoint,cap ; bls keep ; cbz cap keep ; strh cap,[+0x16]. */
        if ((cc.setpoint > cc.cap) && (cc.cap != 0u)) {
            cc.setpoint = cc.cap;
        }
    }

    /* target voltage = H102.TargetBatteryVoltage ; cbz -> skip when 0. */
    uint16_t tv = in->target_voltage;
    if (tv != 0u) {
        cc.target_v_raw = tv;   /* +0x1e uncapped */
        cc.target_v     = tv;   /* +0x1c */
        /* voltage limit p[+0x216]: cbz skip ; cmp limit,target ; bhi keep ; strh limit,[+0x1c]. */
        uint16_t lim = in->voltage_limit;
        if ((lim != 0u) && (lim <= cc.target_v)) {
            cc.target_v = lim;
        }
    }
}

const current_ctrl_t *current_ctrl_get(void)
{
    return &cc;
}