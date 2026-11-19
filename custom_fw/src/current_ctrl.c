/* current_ctrl.c — INERT H102 output-current control law (shadow), REPORT §5.21 E.
 * Byte-exact replica of the C013 state-30 CurrentDemand block 0x08044D42–0x08044DBC
 * (analyze89). Computes the output-current setpoint + target voltage; drives NO power stage.
 */
#include "current_ctrl.h"

static current_ctrl_t cc;

int32_t current_ctrl_converter(int8_t code)
{
    /* 0x0804E786: sxtb r0,r0 ; cmp r0,#7 ; blt keep ; movs r0,#0xff ; bx lr */
    int32_t x = (int32_t)code;   /* sxtb: sign-extend the byte */
    if (x < 7) {                 /* blt (signed) */
        return x;
    }
    return 0xFF;
}

uint16_t current_ctrl_scale(uint16_t raw, int8_t factor)
{
    /* muls r0,r1,r0 (32-bit low word) ; udiv r0,r0,fp (#1000) ; strh (low 16) */
    uint32_t f = (uint32_t)current_ctrl_converter(factor);
    uint32_t prod = (uint32_t)raw * f;   /* low 32 bits of the product */
    return (uint16_t)(prod / 1000u);
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