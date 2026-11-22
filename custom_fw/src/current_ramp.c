/* current_ramp.c — INERT periodic EVMaximumCurrentLimit ramp (shadow), REPORT §5.17 G11.
 * Byte-exact replica of the C013 state-30 CurrentDemand ramp block 0x0804BB54–0x0804BBE8
 * (analyze105). Ramps the requested current limit +20 A/min tracking the EVSE present current,
 * clamped to the EVSE max; drives NO power stage. See current_ramp.h for the decoded law.
 */
#include "current_ramp.h"

#define RAMP_INIT_A       20u    /* movs #0x14 at state-17 (0x0804ABCA) + state-30 entry      */
#define RAMP_STEP_A       20u    /* adds #0x14 (both paths)                                   */
#define RAMP_FINE_DB      5u     /* subs/adds #5 fine deadband                                */
#define RAMP_COARSE_DB    25u    /* sub.w #0x19 ; adds #0x32 -> ±25 coarse deadband           */
#define RAMP_FINE_PERIOD  6000u  /* movw #0x1770 = 6000 ticks = 60 s = 1 min @100 Hz          */
#define RAMP_COARSE_GATE  600u   /* cmp p[+0x64],#0x258 = 600                                 */

static current_ramp_t cr;

void current_ramp_init(void)
{
    cr.setpoint  = RAMP_INIT_A;
    cr.ceiling   = 0;
    cr.max_limit = 0;
}

/* Coarse path B (0x0804BBB2–0x0804BBDA): return 1 if a +20 step is allowed. All compares are
 * 32-bit unsigned on the zero-extended halfword setpoint, mirroring the firmware exactly. */
static int coarse_allow(uint32_t sp, uint32_t tgt, uint32_t ceil, uint32_t p64)
{
    if (tgt >= ceil) return 0;             /* ldr [sp,#0x18] ; cmp r1,r0 ; bhs exit          */
    if (ceil == 0u)  return 0;             /* cbz r0 exit                                    */
    if (p64 < RAMP_COARSE_GATE) return 0;  /* ldr [r4,#0x64] ; cmp #0x258 ; blo exit         */
    uint32_t lo = sp - RAMP_COARSE_DB;     /* sub.w r2,r1,#0x19 (wraps high when sp < 25)    */
    if (lo > tgt) return 0;                /* cmp r2,r3 ; bhi exit                           */
    uint32_t hi = lo + 2u * RAMP_COARSE_DB;/* adds r2,#0x32 -> (sp-25)+50 = sp+25 mod 2^32   */
    if (hi < tgt) return 0;                /* cmp r2,r3 ; blo exit                           */
    return 1;
}

void current_ramp_step(const current_ramp_inputs_t *in)
{
    const uint32_t tgt  = in->target;   /* [sp+0x18] = din_scale(EVSE present current) */
    const uint32_t ceil = in->ceiling;  /* [fp+0x2c] = din_scale(EVSE max current)     */
    cr.ceiling = in->ceiling;

    /* 0x0804BB54: ldrh p[+0x4] ; udiv/mls #10 ; cbnz exit — run only every 10 ticks. */
    if ((in->phase_cnt % 10u) == 0u) {
        uint32_t sp = cr.setpoint;       /* ldrh [r6,#0x28c], zero-extended to 32 bits */
        int step = 0;

        /* 0x0804BB68: cmp target,ceiling ; bhs coarse ; cbz ceiling coarse. */
        if (tgt < ceil && ceil != 0u) {
            /* FINE path: ±5 A deadband (subs r3,r1,#5 / adds r3,r1,#5 vs ip=target). */
            uint32_t lo = sp - RAMP_FINE_DB;
            uint32_t hi = sp + RAMP_FINE_DB;
            if (lo <= tgt && hi >= tgt) {
                /* In band: +20 gated on phase_cnt % 6000 == 0 (cbnz -> exit, NOT coarse). */
                if ((in->phase_cnt % RAMP_FINE_PERIOD) == 0u) step = 1;
            } else {
                /* Outside ±5 -> coarse path B (setpoint re-loaded unchanged at 0x0804BBC2). */
                step = coarse_allow(sp, tgt, ceil, in->p64);
            }
        } else {
            step = coarse_allow(sp, tgt, ceil, in->p64);
        }

        if (step) {
            sp += RAMP_STEP_A;           /* adds r1,#0x14                                  */
            sp &= 0xFFFFu;               /* uxth r1,r1                                     */
            if (sp >= ceil) sp = ceil;   /* cmp r1,r0 ; blo skip ; strh r0,[r6,#0x28c]     */
            cr.setpoint = (uint16_t)sp;
        }
    }

    /* EVMaximumCurrentLimit = min(ramped setpoint, ceiling) — 0x0804EA94: ldrh [r6,#0x28c] ;
     * cmp r0,r5 ; bhi keep ceiling ; mov r5,r0. Recomputed every demand regardless of step. */
    cr.max_limit = (cr.setpoint < cr.ceiling) ? cr.setpoint : cr.ceiling;
}

const current_ramp_t *current_ramp_get(void)
{
    return &cr;
}