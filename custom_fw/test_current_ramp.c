/* test_current_ramp.c — host unit test for the INERT periodic EVMaximumCurrentLimit ramp
 * (custom_fw/src/current_ramp.c, REPORT §5.17 G11, byte-derived 0x0804BB54–0x0804BBE8).
 *
 * Build + run (host gcc; freestanding module, no library deps):
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_current_ramp \
 *       test_current_ramp.c src/current_ramp.c && ./test_current_ramp'
 *
 * Verifies: the 20 A init, the phase_cnt%10 gate, the FINE +20 A/6000-tick (1 min) ramp with the
 * ±5 A deadband, the COARSE +20 A/10-tick catch-up with the ±25 A deadband + p[+0x64]>=600 gate,
 * the 32-bit unsigned deadband math (incl. the -25 wrap at the 20 A init), the ceiling clamp, the
 * EVMaximumCurrentLimit = min(ramped, ceiling) output, and the inert-safety property (EVSE stubs 0
 * -> ceiling 0 -> no step, max_limit 0).
 */
#include <stdio.h>
#include <stdint.h>
#include "current_ramp.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

static current_ramp_inputs_t in_buf;
static const current_ramp_inputs_t *in(uint16_t target, uint16_t ceiling,
                                       uint16_t phase_cnt, uint32_t p64)
{
    in_buf.target    = target;
    in_buf.ceiling   = ceiling;
    in_buf.phase_cnt = phase_cnt;
    in_buf.p64       = p64;
    return &in_buf;
}

int main(void)
{
    const current_ramp_t *r;

    /* --- init: setpoint 20 A (stock movs #0x14), ceiling/max_limit 0 --- */
    current_ramp_init();
    r = current_ramp_get();
    CHECK(r->setpoint == 20,  "init setpoint 20 A");
    CHECK(r->ceiling == 0,    "init ceiling 0");
    CHECK(r->max_limit == 0,  "init max_limit 0");

    /* --- inert safety: EVSE stubs 0 -> ceiling 0 -> coarse exit, no step, max_limit 0 --- */
    current_ramp_init();
    current_ramp_step(in(0, 0, 6000, 0));
    r = current_ramp_get();
    CHECK(r->setpoint == 20,  "inert: ceiling 0 -> setpoint held 20");
    CHECK(r->max_limit == 0,  "inert: max_limit min(20,0)=0");
    /* even a vehicle request present cannot raise the limit with no EVSE capability */
    current_ramp_step(in(100, 0, 12000, 1000));
    r = current_ramp_get();
    CHECK(r->setpoint == 20,  "inert: target 100 ceiling 0 -> no step");
    CHECK(r->max_limit == 0,  "inert: max_limit stays 0");

    /* --- phase_cnt % 10 gate: 6001 not divisible by 10 -> no step --- */
    current_ramp_init();
    current_ramp_step(in(20, 200, 6001, 0));   /* otherwise fine-eligible */
    r = current_ramp_get();
    CHECK(r->setpoint == 20,  "%10 gate: 6001 -> no step");
    CHECK(r->max_limit == 20, "%10 gate: max_limit min(20,200)=20");

    /* --- FINE ramp: +20 A every 6000 ticks tracking the EVSE present current --- */
    current_ramp_init();                          /* setpoint 20 */
    current_ramp_step(in(20, 200, 6000, 0));      /* 20 in [15,25], %6000==0 -> 40 */
    r = current_ramp_get();
    CHECK(r->setpoint == 40,  "fine: 20 -> 40 at 6000 ticks");
    CHECK(r->max_limit == 40, "fine: max_limit 40");
    current_ramp_step(in(40, 200, 12000, 0));     /* 40 in [35,45] -> 60 */
    r = current_ramp_get();
    CHECK(r->setpoint == 60,  "fine: 40 -> 60 at 12000 ticks");
    current_ramp_step(in(60, 200, 18000, 0));     /* -> 80 */
    r = current_ramp_get();
    CHECK(r->setpoint == 80,  "fine: 60 -> 80 at 18000 ticks");
    CHECK(r->max_limit == 80, "fine: max_limit tracks setpoint 80");

    /* fine step only at %6000==0: 6010 (%10==0, %6000!=0) in band -> NO step */
    current_ramp_init();
    current_ramp_step(in(20, 200, 6010, 0));
    r = current_ramp_get();
    CHECK(r->setpoint == 20,  "fine: %6000!=0 (6010) in band -> no step");

    /* --- FINE ±5 deadband boundaries (setpoint 20) --- */
    current_ramp_init();
    current_ramp_step(in(15, 200, 6000, 0));      /* lo bound 20-5=15 -> in band -> 40 */
    r = current_ramp_get();
    CHECK(r->setpoint == 40,  "fine: target==setpoint-5 (15) in band -> step");
    current_ramp_init();
    current_ramp_step(in(25, 200, 6000, 0));      /* hi bound 20+5=25 -> in band -> 40 */
    r = current_ramp_get();
    CHECK(r->setpoint == 40,  "fine: target==setpoint+5 (25) in band -> step");
    /* target 14 (< setpoint-5) -> coarse; coarse -25 wraps high at sp 20 -> blocked */
    current_ramp_init();
    current_ramp_step(in(14, 200, 6000, 1000));
    r = current_ramp_get();
    CHECK(r->setpoint == 20,  "fine: target 14 outside -5 -> coarse wrap blocks");
    /* target 26 (> setpoint+5) -> coarse; coarse -25 wraps high at sp 20 -> blocked */
    current_ramp_init();
    current_ramp_step(in(26, 200, 6000, 1000));
    r = current_ramp_get();
    CHECK(r->setpoint == 20,  "fine: target 26 outside +5 -> coarse wrap blocks");

    /* --- COARSE catch-up: setpoint 60, target lags by 20 (within ±25, outside ±5) --- */
    current_ramp_init();
    current_ramp_step(in(20, 200, 6000, 0));      /* 20 -> 40 */
    current_ramp_step(in(40, 200, 12000, 0));     /* 40 -> 60 */
    r = current_ramp_get();
    CHECK(r->setpoint == 60,  "coarse setup: setpoint 60");
    /* phase_cnt 12010 (%10==0, %6000!=0); target 40 -> fine lo 55>40 outside -> coarse.
     * p64 600 >= 600, coarse lo 35<=40, hi 85>=40 -> +20 -> 80 (every 10 ticks). */
    current_ramp_step(in(40, 200, 12010, 600));
    r = current_ramp_get();
    CHECK(r->setpoint == 80,  "coarse: lag 20 within ±25, p64 600 -> +20 -> 80");
    current_ramp_step(in(40, 200, 12020, 600));   /* now lag 40: coarse lo 80-25=55>40 -> exit */
    r = current_ramp_get();
    CHECK(r->setpoint == 80,  "coarse: now lag 40 outside ±25 -> no step");

    /* coarse p[+0x64] gate: p64 599 < 600 -> no step */
    current_ramp_init();
    current_ramp_step(in(20, 200, 6000, 0));      /* 40 */
    current_ramp_step(in(40, 200, 12000, 0));     /* 60 */
    current_ramp_step(in(40, 200, 12010, 599));
    r = current_ramp_get();
    CHECK(r->setpoint == 60,  "coarse: p64 599 < 600 -> no step");

    /* coarse ±25 deadband boundaries (setpoint 60, p64 600, %10 tick) */
    current_ramp_init();
    current_ramp_step(in(20, 200, 6000, 0));      /* 40 */
    current_ramp_step(in(40, 200, 12000, 0));     /* 60 */
    current_ramp_step(in(35, 200, 12010, 600));   /* lo bound 60-25=35 -> step -> 80 */
    r = current_ramp_get();
    CHECK(r->setpoint == 80,  "coarse: target==setpoint-25 (35) -> step");
    current_ramp_init();
    current_ramp_step(in(20, 200, 6000, 0));      /* 40 */
    current_ramp_step(in(40, 200, 12000, 0));     /* 60 */
    current_ramp_step(in(34, 200, 12010, 600));   /* 34 < 35 -> coarse lo 35>34 exit */
    r = current_ramp_get();
    CHECK(r->setpoint == 60,  "coarse: target 34 outside -25 -> no step");
    current_ramp_init();
    current_ramp_step(in(20, 200, 6000, 0));      /* 40 */
    current_ramp_step(in(40, 200, 12000, 0));     /* 60 */
    current_ramp_step(in(85, 200, 12010, 600));   /* hi 60+25=85: fine hi 65<85 -> coarse hi 85>=85 -> 80 */
    r = current_ramp_get();
    CHECK(r->setpoint == 80,  "coarse: target==setpoint+25 (85) -> step");
    current_ramp_init();
    current_ramp_step(in(20, 200, 6000, 0));      /* 40 */
    current_ramp_step(in(40, 200, 12000, 0));     /* 60 */
    current_ramp_step(in(86, 200, 12010, 600));   /* 86 > 85 -> coarse hi 85<86 exit */
    r = current_ramp_get();
    CHECK(r->setpoint == 60,  "coarse: target 86 outside +25 -> no step");

    /* --- target >= ceiling -> coarse exit (no step) --- */
    current_ramp_init();
    current_ramp_step(in(200, 200, 6000, 1000));
    r = current_ramp_get();
    CHECK(r->setpoint == 20,  "target>=ceiling -> no step");
    CHECK(r->max_limit == 20, "target>=ceiling: max_limit min(20,200)=20");

    /* --- ceiling clamp: setpoint steps then clamps to ceiling --- */
    current_ramp_init();
    current_ramp_step(in(20, 50, 6000, 0));       /* 20 -> 40 (<50) */
    r = current_ramp_get();
    CHECK(r->setpoint == 40,  "clamp setup: 20 -> 40 under ceiling 50");
    current_ramp_step(in(40, 50, 12000, 0));      /* 40+20=60 >=50 -> clamp 50 */
    r = current_ramp_get();
    CHECK(r->setpoint == 50,  "clamp: 60 -> ceiling 50");
    CHECK(r->max_limit == 50, "clamp: max_limit 50");
    current_ramp_step(in(50, 50, 18000, 0));      /* target>=ceiling -> coarse exit; stays 50 */
    r = current_ramp_get();
    CHECK(r->setpoint == 50,  "clamp: holds at ceiling 50");

    /* --- EVMaximumCurrentLimit = min(ramped, ceiling) even when setpoint > ceiling --- */
    current_ramp_init();                          /* setpoint 20 */
    current_ramp_step(in(5, 10, 6000, 1000));     /* ceiling 10 < setpoint 20; no step (coarse wrap) */
    r = current_ramp_get();
    CHECK(r->setpoint == 20,  "min: setpoint stays 20 (ceiling 10)");
    CHECK(r->max_limit == 10, "min: max_limit min(20,10)=10");
    CHECK(r->ceiling == 10,   "min: ceiling recorded 10");

    /* --- re-init resets to 20 A (state-30 re-entry) --- */
    current_ramp_step(in(20, 200, 6000, 0));      /* would step, but... */
    current_ramp_init();
    r = current_ramp_get();
    CHECK(r->setpoint == 20,  "re-init resets setpoint to 20");
    CHECK(r->max_limit == 0,  "re-init resets max_limit to 0");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}