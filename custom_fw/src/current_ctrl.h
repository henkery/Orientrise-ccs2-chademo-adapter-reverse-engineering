/* current_ctrl.h — INERT H102 output-current control law (shadow), REPORT §5.21 E.
 *
 * Faithful replica of the C013 state-30 CurrentDemand output-current setpoint computation,
 * byte-derived at 0x08044D42–0x08044DBC (analyze89). It turns the vehicle's H102 charging
 * request into an output-current setpoint + target voltage, clamped to the EVSE's capability:
 *
 *   cap      = scale(EVSE_max_raw,   EVSE_max_factor)          -> ctx.cap        (+0x1a)
 *   avail    = scale(EVSE_avail_raw, EVSE_avail_factor)
 *   setpoint = min(H102.ChargingCurrentRequest, avail)         -> ctx.setpoint_raw (+0x18)
 *   if setpoint > cap && cap != 0: setpoint = cap              -> ctx.setpoint   (+0x16)
 *   target_v = H102.TargetBatteryVoltage                       -> ctx.target_v_raw (+0x1e)
 *   if voltage_limit != 0 && voltage_limit <= target_v:
 *        target_v = voltage_limit                              -> ctx.target_v   (+0x1c)
 *
 *   scale(raw, factor) = (uint16)((uint32)raw * converter(factor) / 1000)   (muls + udiv #1000)
 *   converter(code)    = (code < 7) ? code : 0xFF   (sxtb + signed blt; 0x0804E786)
 *
 * The zero-skip paths are preserved: a zero min(request,avail) leaves the current setpoint
 * unchanged, and a zero target voltage leaves the target voltage unchanged (the firmware
 * `cbz` skips those stores). cap is written unconditionally.
 *
 * INERT / SHADOW: this computes the setpoint the power stage WOULD be commanded to, but drives
 * NO GPIO / DAC / PWM. The asserted power-stage drive is a later GATED layer (compile-time safety
 * flag). The EVSE-side measurements (max/avail current + factors, voltage limit) come from the
 * CCS2 PLC/DIN subsystem that is NOT built yet — main feeds safe stubs (0), so avail==0 and the
 * min(request,0)==0 zero-skip holds the setpoint at 0: no current is ever commanded. Pure helpers
 * (converter/scale) + the step law are host-unit-tested (custom_fw/test_current_ctrl.c).
 */
#ifndef CURRENT_CTRL_H
#define CURRENT_CTRL_H
#include <stdint.h>

/* Shadow output-current context — mirrors the stock 0x20000780 setpoint fields. */
typedef struct {
    uint16_t setpoint;      /* +0x16 capped output-current setpoint (A)        */
    uint16_t setpoint_raw;  /* +0x18 uncapped min(request, avail) (A)          */
    uint16_t cap;           /* +0x1a EVSE max-current cap (A)                  */
    uint16_t target_v;      /* +0x1c capped target battery voltage (V)         */
    uint16_t target_v_raw;  /* +0x1e uncapped target battery voltage (V)       */
} current_ctrl_t;

/* Inputs: CHAdeMO H102 (vehicle) side + EVSE (CCS2 PLC) side measurements. The EVSE-side fields
 * are stubbed 0 by main until the CCS2 subsystem exists. */
typedef struct {
    uint8_t  current_request;    /* H102 byte3 ChargingCurrentRequest p[+0x1dc] (A) */
    uint16_t target_voltage;     /* H102 byte1-2 TargetBatteryVoltage p[+0x1da] (V) */
    uint16_t evse_max_raw;       /* EVSE max-current raw halfword @0x3D20           */
    int8_t   evse_max_factor;    /* EVSE max-current range-code byte @0x3D22        */
    uint16_t evse_avail_raw;     /* EVSE present/available raw halfword ([sp+0x48]) */
    int8_t   evse_avail_factor;  /* EVSE present range-code byte                    */
    uint16_t voltage_limit;      /* output-voltage limit p[+0x216] (V)              */
} current_ctrl_inputs_t;

void current_ctrl_init(void);
/* Apply the state-30 CurrentDemand law once (INERT: updates the shadow context only). */
void current_ctrl_step(const current_ctrl_inputs_t *in);
const current_ctrl_t *current_ctrl_get(void);

/* Pure, host-testable helpers (byte-exact vs the firmware). */
/* 0x0804E786: sxtb then `cmp #7; blt keep; movs #0xff`. Signed compare on the sign-extended byte. */
int32_t  current_ctrl_converter(int8_t code);
/* muls raw*converter(factor) (low 32) ; udiv /1000 ; strh (low 16). */
uint16_t current_ctrl_scale(uint16_t raw, int8_t factor);

#endif /* CURRENT_CTRL_H */