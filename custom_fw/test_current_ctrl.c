/* test_current_ctrl.c — host unit test for the INERT H102 output-current control law
 * (custom_fw/src/current_ctrl.c, REPORT §5.21 E, byte-derived 0x08044D42–0x08044DBC).
 *
 * Build + run (host gcc; links the shared DIN PhysicalValueType scaling din70121.c + exi.c):
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_current_ctrl \
 *       test_current_ctrl.c src/current_ctrl.c src/din70121.c src/exi.c && ./test_current_ctrl'
 *
 * Verifies: the power-of-10 scaling converter (0x0804E786 table lookup, CORRECTED from
 * analyze89's identity reading), the muls/udiv/strh /1000 scaling (real = raw*10^(factor-3)),
 * the min(request,avail) + EVSE-max cap law, the target-voltage min limit, the zero-skip
 * "keep previous" paths, and the inert-safety property (EVSE stubs -> setpoint 0).
 */
#include <stdio.h>
#include <stdint.h>
#include "current_ctrl.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

static current_ctrl_inputs_t in_zero(void)
{
    current_ctrl_inputs_t in;
    in.current_request   = 0;
    in.target_voltage    = 0;
    in.evse_max_raw      = 0;
    in.evse_max_factor   = 0;
    in.evse_avail_raw    = 0;
    in.evse_avail_factor = 0;
    in.voltage_limit     = 0;
    return in;
}

int main(void)
{
    /* --- converter 0x0804E786: cmp #7 ; blt -> pow10 TABLE[code] ; else 0xFF --- */
    CHECK(current_ctrl_converter(0) == 1,       "converter(0)==pow10[0]==1");
    CHECK(current_ctrl_converter(1) == 10,      "converter(1)==pow10[1]==10");
    CHECK(current_ctrl_converter(3) == 1000,    "converter(3)==pow10[3]==1000");
    CHECK(current_ctrl_converter(6) == 1000000, "converter(6)==pow10[6]==1000000");
    CHECK(current_ctrl_converter(7) == 0xFF,    "converter(7)==0xFF");
    CHECK(current_ctrl_converter(100) == 0xFF,  "converter(100)==0xFF");
    CHECK(current_ctrl_converter(127) == 0xFF,  "converter(127)==0xFF");
    CHECK(current_ctrl_converter(-1) == 0xFF,   "converter(-1)==0xFF (out-of-table safe)");
    CHECK(current_ctrl_converter(-128) == 0xFF, "converter(-128)==0xFF (out-of-table safe)");

    /* --- scale: muls raw*pow10(factor) ; udiv /1000 ; strh low16. real=raw*10^(factor-3) --- */
    CHECK(current_ctrl_scale(1000, 3) == 1000,  "scale(1000,3)==1000 (mult 0 identity)");
    CHECK(current_ctrl_scale(1000, 2) == 100,   "scale(1000,2)==100 (mult -1)");
    CHECK(current_ctrl_scale(1000, 4) == 10000, "scale(1000,4)==10000 (mult +1)");
    CHECK(current_ctrl_scale(1000, 0) == 1,     "scale(1000,0)==1 (mult -3)");
    CHECK(current_ctrl_scale(0, 5) == 0,        "scale(0,5)==0");
    CHECK(current_ctrl_scale(500, 2) == 50,     "scale(500,2)==50");
    CHECK(current_ctrl_scale(1000, 7) == 255,   "scale(1000,7)==255 (clamp)");
    CHECK(current_ctrl_scale(65535, 3) == 65535,"scale(65535,3)==65535");
    CHECK(current_ctrl_scale(1000, 6) == 16960, "scale(1000,6)==16960 (low16 of 1000000)");

    /* --- inert safety: all EVSE stubs 0 -> avail 0 -> min 0 -> setpoint stays 0 --- */
    current_ctrl_init();
    current_ctrl_inputs_t in = in_zero();
    in.current_request = 100;   /* vehicle asks for current, but EVSE capability unknown */
    in.target_voltage  = 400;
    current_ctrl_step(&in);
    const current_ctrl_t *c = current_ctrl_get();
    CHECK(c->setpoint == 0,     "inert: EVSE avail stub 0 -> setpoint 0");
    CHECK(c->setpoint_raw == 0, "inert: setpoint_raw 0");
    CHECK(c->cap == 0,          "inert: cap 0");
    CHECK(c->target_v == 400,   "target voltage passes through (no limit)");
    CHECK(c->target_v_raw == 400, "target_v_raw 400");

    /* --- min(request,avail) then cap by EVSE max (factor 3 = mult 0 = identity scaling) --- */
    current_ctrl_init();
    in = in_zero();
    in.current_request   = 50;
    in.evse_avail_raw    = 60; in.evse_avail_factor = 3;  /* avail = 60 */
    in.evse_max_raw      = 40; in.evse_max_factor   = 3;  /* cap   = 40 */
    in.target_voltage    = 400;
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->cap == 40,          "cap = scale(40,3) = 40");
    CHECK(c->setpoint_raw == 50, "setpoint_raw = min(50,60) = 50 (uncapped)");
    CHECK(c->setpoint == 40,     "setpoint capped 50 -> 40");
    CHECK(c->target_v == 400,    "target_v 400");

    /* request below avail and below cap -> no capping */
    current_ctrl_init();
    in.current_request = 30;
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->setpoint_raw == 30, "setpoint_raw = min(30,60) = 30");
    CHECK(c->setpoint == 30,     "setpoint 30 (<= cap, uncapped)");

    /* request above avail -> clamped to avail, then to cap */
    current_ctrl_init();
    in.current_request = 100;
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->setpoint_raw == 60, "setpoint_raw = min(100,60) = 60");
    CHECK(c->setpoint == 40,     "setpoint 60 -> cap 40");

    /* cap == 0 -> no cap applied (cbz cap keep) */
    current_ctrl_init();
    in = in_zero();
    in.current_request = 50;
    in.evse_avail_raw  = 60; in.evse_avail_factor = 3;  /* avail 60, cap 0 */
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->cap == 0,           "cap 0");
    CHECK(c->setpoint == 50,     "cap==0 -> setpoint stays 50 (no cap)");
    CHECK(c->setpoint_raw == 50, "setpoint_raw 50");

    /* request == avail boundary (bhs keeps avail) */
    current_ctrl_init();
    in.current_request = 60;
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->setpoint_raw == 60, "request==avail -> 60");

    /* --- target-voltage min limit p[+0x216] --- */
    current_ctrl_init();
    in = in_zero();
    in.target_voltage = 400;
    in.voltage_limit  = 350;
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->target_v_raw == 400, "target_v_raw 400 (uncapped)");
    CHECK(c->target_v == 350,     "target_v capped 400 -> 350");

    current_ctrl_init();
    in.voltage_limit = 450;       /* limit > target -> keep */
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->target_v == 400,     "limit>target -> target_v stays 400");

    current_ctrl_init();
    in.voltage_limit = 400;       /* limit == target -> target = limit */
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->target_v == 400,     "limit==target -> 400");

    /* --- zero-skip keeps previous setpoint / target --- */
    current_ctrl_init();
    in = in_zero();
    in.current_request = 50;
    in.evse_avail_raw  = 60; in.evse_avail_factor = 3;
    in.evse_max_raw    = 40; in.evse_max_factor   = 3;
    in.target_voltage  = 400;
    current_ctrl_step(&in);       /* setpoint 40, target_v 400 */
    in.current_request = 0;       /* min(0,60)=0 -> skip current stores */
    in.target_voltage  = 0;       /* skip voltage stores */
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->setpoint == 40,      "zero-skip: setpoint kept 40");
    CHECK(c->setpoint_raw == 50,  "zero-skip: setpoint_raw kept 50");
    CHECK(c->target_v == 400,     "zero-skip: target_v kept 400");
    CHECK(c->cap == 40,           "cap recomputed (40) even on zero-skip");

    /* avail collapses to 0 (EVSE lost) -> min 0 -> setpoint kept (not forced up) */
    in.evse_avail_raw = 0;
    in.current_request = 100;
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->setpoint == 40,      "avail 0 -> min 0 -> setpoint kept 40");

    /* --- factor clamp inside scale (avail factor 7 -> 255) --- */
    current_ctrl_init();
    in = in_zero();
    in.current_request   = 200;
    in.evse_avail_raw    = 1000; in.evse_avail_factor = 7;   /* avail = 255 */
    in.evse_max_raw      = 60; in.evse_max_factor  = 3;      /* cap = 60 */
    current_ctrl_step(&in);
    c = current_ctrl_get();
    CHECK(c->setpoint_raw == 200, "min(200,255)=200");
    CHECK(c->setpoint == 60,      "200 -> cap 60");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}