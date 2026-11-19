/* test_charge_stm.c — HOST unit test for the inert CHAdeMO charge state machine (REPORT §5.17).
 * Compiles charge_stm.c on the host (no hardware) and checks:
 *   1. the byte-exact state-17 engagement guard window/thresholds (0x0804AF08–0x0804AF30),
 *   2. the safe-charge sequence walk + state-17 stall/timeout + valid-EVSE engagement,
 *   3. the safety interlocks (whole-bus loss, H102 fault, emergency) forcing a safe stop.
 * The CAN-layer bus-freshness helper is stubbed (g_bus_fresh) so the watchdog is directly driven.
 *
 * Run:  gcc -O2 -Wall -Wextra -Isrc -o test_charge_stm test_charge_stm.c src/charge_stm.c && ./test_charge_stm
 */
#include <stdio.h>
#include <string.h>
#include "charge_stm.h"

/* host stub for the CAN-layer helper charge_stm.c calls (real one lives in chademo.c). */
static int g_bus_fresh = 1;
int chademo_bus_fresh(uint32_t tick) { (void)tick; return g_bus_fresh; }

static int failures = 0, checks = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } } while (0)

static chademo_vehicle_t veh;
static charge_stm_inputs_t in;
static uint32_t t;

/* keep the per-message + whole-bus watchdogs fresh at the current tick */
static void step(void)
{
    t++;
    veh.h100_seen = veh.h101_seen = veh.h102_seen = 1;
    veh.last_h100 = veh.last_h101 = veh.last_h102 = t;
    charge_stm_step(t, &in, &veh);
}

static void reset_all(void)
{
    charge_stm_init();
    memset(&veh, 0, sizeof veh);
    memset(&in, 0, sizeof in);
    g_bus_fresh = 1;
    t = 0;
    veh.target_voltage = 400;      /* ress_vol = 400 V */
    veh.current_request = 50;      /* >0 A */
    in.outvol = 400;               /* EVSE output matched to battery */
}

/* walk IDLE -> 13 -> 14 -> 15 -> 16 -> 17 using the handshake inputs */
static void walk_to_volt_match(void)
{
    step();                                   /* IDLE (no plug_in yet) */
    in.plug_in = 1;        step();            /* -> 13 */
    in.cablecheck_fin = 1; step();            /* -> 14 */
    in.chgparam_ok = 1;    step();            /* -> 15 */
    in.ev_contactor = 1;   step();            /* -> 16 */
    step();                                   /* current_request>0 -> 17 */
}

static void test_guard(void)
{
    const uint16_t rv = 400;
    /* window outvol ∈ [ress_vol−10, ress_vol+5] */
    CHECK(charge_stm_engage_ok(390, rv, 250, 4, 1) == 1, "guard: outvol=ress-10 lower bound pass");
    CHECK(charge_stm_engage_ok(405, rv, 250, 4, 1) == 1, "guard: outvol=ress+5 upper bound pass");
    CHECK(charge_stm_engage_ok(389, rv, 250, 4, 1) == 0, "guard: outvol=ress-11 below window fail");
    CHECK(charge_stm_engage_ok(406, rv, 250, 4, 1) == 0, "guard: outvol=ress+6 above window fail");
    CHECK(charge_stm_engage_ok(400, rv, 250, 4, 1) == 1, "guard: outvol=ress exact pass");
    /* dwell counter threshold 250 */
    CHECK(charge_stm_engage_ok(400, rv, 249, 4, 1) == 0, "guard: cnt=249 fail");
    CHECK(charge_stm_engage_ok(400, rv, 250, 4, 1) == 1, "guard: cnt=250 pass");
    CHECK(charge_stm_engage_ok(400, rv, 65535, 4, 1) == 1, "guard: cnt large pass");
    /* isolation must be exactly 4 */
    CHECK(charge_stm_engage_ok(400, rv, 250, 3, 1) == 0, "guard: isolation=3 fail");
    CHECK(charge_stm_engage_ok(400, rv, 250, 0, 1) == 0, "guard: isolation=0 fail");
    CHECK(charge_stm_engage_ok(400, rv, 250, 5, 1) == 0, "guard: isolation=5 fail");
    /* flag must be exactly 1 */
    CHECK(charge_stm_engage_ok(400, rv, 250, 4, 0) == 0, "guard: flag=0 fail");
    CHECK(charge_stm_engage_ok(400, rv, 250, 4, 2) == 0, "guard: flag=2 fail");
    /* unsigned wrap: outvol<5 -> outvol-5 wraps high -> fail (matches subs+bhi) */
    CHECK(charge_stm_engage_ok(0, 0, 250, 4, 1) == 0, "guard: outvol=0 ress=0 wrap fail");
    CHECK(charge_stm_engage_ok(4, 0, 250, 4, 1) == 0, "guard: outvol=4 ress=0 wrap fail");
    CHECK(charge_stm_engage_ok(5, 0, 250, 4, 1) == 1, "guard: outvol=5 ress=0 pass");
    /* high voltage, no 16-bit overflow in the window math */
    CHECK(charge_stm_engage_ok(1000, 1000, 250, 4, 1) == 1, "guard: 1000V pass");
    CHECK(charge_stm_engage_ok(990, 1000, 250, 4, 1) == 1, "guard: 990/1000 lower bound pass");
    CHECK(charge_stm_engage_ok(1005, 1000, 250, 4, 1) == 1, "guard: 1005/1000 upper bound pass");
    CHECK(charge_stm_engage_ok(1006, 1000, 250, 4, 1) == 0, "guard: 1006/1000 above window fail");
}

static void test_sequence_stall(void)
{
    reset_all();
    walk_to_volt_match();
    CHECK(charge_stm_state() == STM_VOLT_MATCH, "seq: reach state 17");
    /* EVSE-side stubs (isolation=0, flag=0): guard must NOT engage; stays in 17 */
    for (int i = 0; i < 100; i++) step();
    CHECK(charge_stm_state() == STM_VOLT_MATCH, "seq: stubbed EVSE stalls in 17 (no engagement)");
    CHECK(charge_stm_engage_result() == 0, "seq: guard result 0 with stubbed EVSE");
    /* state-17 wait counter times out at 424 -> 450 (safe wait/error) */
    for (int i = 0; i < 400; i++) step();
    CHECK(charge_stm_state() == STM_WAIT_ERROR, "seq: state-17 wait timeout -> 450");
    CHECK((charge_stm_interlock() & STM_IL_TIMEOUT) != 0, "seq: timeout interlock recorded");
    CHECK(charge_stm_action() == STM_ACT_ALL_OFF, "seq: wait/error action = all-off (safe)");
}

static void test_sequence_engage(void)
{
    reset_all();
    walk_to_volt_match();
    CHECK(charge_stm_state() == STM_VOLT_MATCH, "seq2: reach state 17");
    /* valid EVSE-side inputs: isolation=4, flag=1, outvol in window -> engage after 250 dwell */
    in.isolation = 4; in.precharge_flag = 1;
    for (int i = 0; i < 249; i++) step();
    CHECK(charge_stm_state() == STM_VOLT_MATCH, "seq2: still 17 before 250 dwell");
    step();   /* 250th dwell tick */
    CHECK(charge_stm_state() == STM_PRECHG_RELAY, "seq2: engagement at 250 dwell -> 18");
    CHECK(charge_stm_engage_result() == 1, "seq2: guard result 1 on engagement");
    CHECK(charge_stm_action() == STM_ACT_PRECHG_RELAY, "seq2: intended action = precharge relay (GATED)");
    /* precharge relay feedback -> 19 -> 20 -> 30 */
    in.precharge_relay = 1; step();
    CHECK(charge_stm_state() == STM_WAIT_TARGET, "seq2: precharge relay feedback -> 19");
    step();   /* outvol(400) >= ress_vol(400) -> 20 */
    CHECK(charge_stm_state() == STM_CD_PREP, "seq2: wait target reached -> 20");
    in.isolation = 3;   /* CurrentDemand requires isolation==3 */
    step();
    CHECK(charge_stm_state() == STM_CURRENTDEMAND, "seq2: -> 30 CurrentDemand");
    CHECK(charge_stm_action() == STM_ACT_CHARGE, "seq2: intended action = charge (GATED, not executed)");
    /* stay in CurrentDemand while healthy */
    for (int i = 0; i < 200; i++) step();
    CHECK(charge_stm_state() == STM_CURRENTDEMAND, "seq2: holds CurrentDemand while healthy");
}

static void test_interlocks(void)
{
    /* H102 fault from CurrentDemand -> 300 (h102_status error) */
    reset_all(); walk_to_volt_match();
    in.isolation = 4; in.precharge_flag = 1;
    for (int i = 0; i < 250; i++) step();      /* engage -> 18 */
    in.precharge_relay = 1; step();            /* -> 19 */
    step();                                    /* -> 20 */
    in.isolation = 3; step();                  /* -> 30 */
    CHECK(charge_stm_state() == STM_CURRENTDEMAND, "il: in CurrentDemand");
    veh.h102_fault5 = 0x88;                    /* VoltageDeviation+CurrentDeviation */
    step();
    CHECK(charge_stm_state() == STM_TIMEOUT_STOP, "il: H102 fault -> 300");
    CHECK((charge_stm_interlock() & STM_IL_H102_FAULT) != 0, "il: H102 fault interlock recorded");

    /* emergency_flag from CurrentDemand -> 40 (stop by charger) */
    reset_all(); walk_to_volt_match();
    in.isolation = 4; in.precharge_flag = 1;
    for (int i = 0; i < 250; i++) step();
    in.precharge_relay = 1; step(); step();
    in.isolation = 3; step();
    in.emergency = 1; step();
    CHECK(charge_stm_state() == STM_STOP_CHARGER, "il: emergency -> 40");
    CHECK((charge_stm_interlock() & STM_IL_EMERGENCY) != 0, "il: emergency interlock recorded");

    /* whole-bus loss from CurrentDemand -> 450 (CAN-loss safe stop) */
    reset_all(); walk_to_volt_match();
    in.isolation = 4; in.precharge_flag = 1;
    for (int i = 0; i < 250; i++) step();
    in.precharge_relay = 1; step(); step();
    in.isolation = 3; step();
    g_bus_fresh = 0; step();
    CHECK(charge_stm_state() == STM_WAIT_ERROR, "il: whole-bus loss -> 450");
    CHECK((charge_stm_interlock() & STM_IL_BUS_LOSS) != 0, "il: bus-loss interlock recorded");

    /* isolation != 3 in CurrentDemand -> 31 (stop by vehicle / isolation warning) */
    reset_all(); walk_to_volt_match();
    in.isolation = 4; in.precharge_flag = 1;
    for (int i = 0; i < 250; i++) step();
    in.precharge_relay = 1; step(); step();
    in.isolation = 3; step();
    in.isolation = 2; step();
    CHECK(charge_stm_state() == STM_STOP_VEH, "il: isolation!=3 in CurrentDemand -> 31");
    CHECK((charge_stm_interlock() & STM_IL_ISOLATION) != 0, "il: isolation interlock recorded");
}

static void test_no_engage_on_mismatch(void)
{
    /* C009 failure mode: outvol far below ress_vol must NEVER engage even after long dwell */
    reset_all();
    walk_to_volt_match();
    in.isolation = 4; in.precharge_flag = 1;
    in.outvol = 357;                 /* ~43 V below the 400 V battery — outside [390,405] */
    for (int i = 0; i < 430; i++) step();
    CHECK(charge_stm_state() != STM_PRECHG_RELAY, "mismatch: never engages at outvol=357/ress=400");
    CHECK(charge_stm_state() == STM_WAIT_ERROR, "mismatch: stalls then wait-timeout -> 450");
}

int main(void)
{
    test_guard();
    test_sequence_stall();
    test_sequence_engage();
    test_interlocks();
    test_no_engage_on_mismatch();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}