/* current_ramp.h — INERT periodic EVMaximumCurrentLimit ramp (shadow), REPORT §5.17 G11.
 *
 * Faithful replica of the C013 state-30 CurrentDemand periodic current-limit ramp, byte-derived
 * at 0x0804BB54–0x0804BBE8 (analyze105). This is the SLOW inrush-limiting layer that is distinct
 * from the per-tick current_ctrl min/cap law (0x08044D42): current_ctrl computes the instantaneous
 * output-current setpoint = min(H102 request, EVSE avail) capped by EVSE max, while THIS module
 * ramps the REQUESTED EVMaximumCurrentLimit (stock meas+0x28C) that the adapter advertises to the
 * EVSE in the CurrentDemandReq, so the EVSE raises its delivered current gradually rather than
 * stepping straight to the full request.
 *
 *   setpoint  = meas+0x28C, init 20 A (0x14) at state-17 (0x0804ABCA) + state-30 entry
 *   target    = din_scale(EVSE present current, meas+0x3D14/16)  ([sp+0x18], writer 0x0804B6E0)
 *   ceiling   = din_scale(EVSE max current,     meas+0x3D20/22)  ([fp+0x2c] = [0x200007AC])
 *
 *   gate: phase_cnt % 10 == 0 (p[+0x4] ticks-in-state, 100 Hz). Then:
 *     if target >= ceiling OR ceiling == 0 -> coarse path B
 *     else FINE: if (setpoint-5) > target OR (setpoint+5) < target -> coarse B   (±5 A deadband)
 *                else if phase_cnt % 6000 != 0 -> exit (no step)
 *                else setpoint += 20 ; clamp to ceiling                          (+20 A / 60 s)
 *     coarse B: if target >= ceiling OR ceiling == 0 OR p[+0x64] < 600 -> exit
 *               if (setpoint-25) > target OR (setpoint+25) < target -> exit      (±25 A deadband)
 *               else setpoint += 20 ; clamp to ceiling                            (+20 A / 10 ticks)
 *
 *   BOTH paths only ADD +20 A (0x14) — there is no decrease in this block. The deadband compares
 *   are 32-bit UNSIGNED on the zero-extended halfword setpoint (subs/adds/sub.w vs the target);
 *   the coarse +25 bound is computed as (setpoint-25)+50 (adds #0x32), so it wraps consistently
 *   when setpoint < 25 (at the 20 A init the coarse -25 bound wraps high and blocks the step).
 *   The +20 step is `adds #0x14 ; uxth ; strh`, clamped `cmp setpoint,ceiling ; blo skip ; strh
 *   ceiling` (setpoint >= ceiling -> ceiling). 6000 ticks = 60 s = 1 minute on the 100 Hz timebase.
 *
 *   EVMaximumCurrentLimit = min(ramped setpoint, ceiling)  (0x0804EA94: ldrh [r6,#0x28c] ;
 *   cmp r0,r5 ; bhi keep ceiling ; mov r5,r0) — the value the CurrentDemandReq advertises.
 *
 * INERT / SHADOW: this computes the current limit the adapter WOULD advertise; it drives NO GPIO /
 * DAC / PWM and the live TCP/TLS send stays gated. With the EVSE measurements stubbed 0 (no live
 * CurrentDemandRes decoded) ceiling == 0, so the ramp never steps and max_limit == min(20,0) == 0:
 * no current limit is ever asserted. Pure step law is host-unit-tested (custom_fw/test_current_ramp.c).
 */
#ifndef CURRENT_RAMP_H
#define CURRENT_RAMP_H
#include <stdint.h>

/* Shadow ramp context — mirrors the stock meas+0x28C ramped setpoint + the advertised limit. */
typedef struct {
    uint16_t setpoint;   /* meas+0x28C ramped current-limit setpoint (A), init 20 */
    uint16_t ceiling;    /* din_scale(EVSE max current) clamp (A) — last input    */
    uint16_t max_limit;  /* EVMaximumCurrentLimit = min(setpoint, ceiling) (A)    */
} current_ramp_t;

/* Inputs: EVSE present/max current (already din_scale'd to A, = current_ctrl avail/cap) + the
 * state-30 tick counter p[+0x4] and the demand-cycle counter p[+0x64] (coarse-path gate >= 600). */
typedef struct {
    uint16_t target;     /* din_scale(EVSE present current) = avail (A)  [sp+0x18] */
    uint16_t ceiling;    /* din_scale(EVSE max current)     = cap (A)    [fp+0x2c] */
    uint16_t phase_cnt;  /* p[+0x4] ticks-in-state (100 Hz)                        */
    uint32_t p64;        /* p[+0x64] demand-cycle counter (coarse gate >= 600)     */
} current_ramp_inputs_t;

/* Init / re-init the ramped setpoint to 20 A (stock state-17 + state-30 entry movs #0x14). */
void current_ramp_init(void);
/* Apply the periodic ramp law once (INERT: updates the shadow context only). */
void current_ramp_step(const current_ramp_inputs_t *in);
const current_ramp_t *current_ramp_get(void);

#endif /* CURRENT_RAMP_H */