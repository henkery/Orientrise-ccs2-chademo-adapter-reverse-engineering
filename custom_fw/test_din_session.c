/* test_din_session.c — host unit test for the autonomous DIN70121 session SM (REPORT §5.9, Agent F).
 * Validates the verified C013 logic (verify_f.py 28/28): state sequence 2->3->6->7->8->9->10->11->
 * 12->13->0, resp-wait retry/re-send + cap 20 -> fault 1, total timeout -> fault 2, CD modulo
 * cadence, CableCheck isolation ==1 advance / ==0 retry / >=2 fault 16, FAILED ResponseCode ->
 * shutdown + fault 40, SessionStop reset. Res bodies synthesized via the exi grammar codec.
 * Pure logic (gcc). Build: gcc -Isrc test_din_session.c src/din_session.c src/din70121.c src/exi.c
 *                          -o test_din_session && ./test_din_session
 */
#include <stdio.h>
#include <string.h>
#include "din_session.h"
#include "din70121.h"
#include "exi.h"

static int checks = 0, failures = 0;
#define CK(c, m) do { checks++; if (!(c)) { failures++; printf("FAIL: %s\n", m); } \
                      else printf("ok: %s\n", m); } while (0)

/* TX hook spy: count sends + record the last event. */
static int tx_count;
static uint8_t tx_last_ev;
static int spy_tx(uint8_t ev, uint8_t *buf, uint16_t cap)
{
    (void)buf; (void)cap;
    tx_count++;
    tx_last_ev = ev;
    return 10;   /* inert image length */
}

/* ---- Res body synthesis (EXI grammar via exi primitives) ---- */
static void wr_dc_evse_status(exi_stream_t *s, uint8_t iso_present, uint8_t iso,
                              uint8_t notif, uint8_t code)
{
    exi_write_bool(s, iso_present);
    if (iso_present) exi_write_bits(s, 2, iso);
    exi_write_bits(s, 2, notif);
    exi_write_bits(s, 4, code);
}
static void wr_pvt(exi_stream_t *s, int8_t mult, uint8_t unit, uint16_t value)
{
    exi_pvt_t p = { .mult = mult, .unit = unit, .unit_present = 1, .value = value };
    exi_write_pvt(s, &p);
}
/* RC-only body (SessionSetup/ServiceDiscovery/CPD/PowerDelivery/Welding Res first field). */
static uint16_t mk_rc(uint8_t *buf, uint8_t rc)
{
    exi_stream_t s; exi_encode_init(&s, buf, 64, 0);
    exi_write_bits(&s, 5, rc);
    return (uint16_t)exi_encode_finish(&s);
}
static uint16_t mk_cablecheck(uint8_t *buf, uint8_t rc, uint8_t iso, uint8_t proc)
{
    exi_stream_t s; exi_encode_init(&s, buf, 64, 0);
    exi_write_bits(&s, 5, rc);
    wr_dc_evse_status(&s, 1, iso, 0, 0);
    exi_write_bits(&s, 1, proc);
    return (uint16_t)exi_encode_finish(&s);
}
static uint16_t mk_precharge(uint8_t *buf, uint8_t rc, uint16_t volt)
{
    exi_stream_t s; exi_encode_init(&s, buf, 64, 0);
    exi_write_bits(&s, 5, rc);
    wr_dc_evse_status(&s, 1, 1, 0, 0);
    wr_pvt(&s, 0, 3, volt);
    return (uint16_t)exi_encode_finish(&s);
}
static uint16_t mk_cd_res(uint8_t *buf, uint8_t rc, uint16_t pv, uint16_t pi)
{
    exi_stream_t s; exi_encode_init(&s, buf, 128, 0);
    exi_write_bits(&s, 5, rc);
    wr_dc_evse_status(&s, 1, 1, 0, 0);
    wr_pvt(&s, 0, 3, pv);          /* EVSEPresentVoltage */
    wr_pvt(&s, 0, 1, pi);          /* EVSEPresentCurrent */
    exi_write_bool(&s, 0);         /* current limit achieved */
    exi_write_bool(&s, 0);         /* voltage limit achieved */
    exi_write_bool(&s, 0);         /* power limit achieved */
    exi_write_bool(&s, 1); wr_pvt(&s, 0, 3, 500);   /* max voltage limit present */
    exi_write_bool(&s, 1); wr_pvt(&s, 0, 1, 200);   /* max current limit present */
    exi_write_bool(&s, 0);         /* max power limit absent */
    return (uint16_t)exi_encode_finish(&s);
}
static uint16_t mk_sessionstop(uint8_t *buf)
{
    exi_stream_t s; exi_encode_init(&s, buf, 16, 0);
    exi_write_bits(&s, 1, 0);      /* empty choice 0 = OK */
    return (uint16_t)exi_encode_finish(&s);
}

static void reset(uint32_t now)
{
    din70121_init();
    din_session_init();
    din_session_set_tx(spy_tx);
    tx_count = 0; tx_last_ev = 0;
    din_session_start(now);
}

static void test_init_start(void)
{
    din70121_init(); din_session_init(); din_session_set_tx(spy_tx);
    const din_session_t *s = din_session_get();
    CK(s->state == DIN_ST_IDLE, "init state IDLE");
    CK(s->resp_wait == 4000 && s->t_total == 120000 && s->t_150 == 150000 &&
       s->t_40 == 40000 && s->t_14 == 14000, "init timers 4000/120000/150000/40000/14000");
    CK(s->fp == 10, "init fp default 10");
    tx_count = 0;
    din_session_start(1000);
    CK(s->state == DIN_ST_SESSIONSETUP_RES, "start -> state 2 (await SessionSetupRes)");
    CK(s->session_active == 1, "start -> session active");
    CK(tx_count == 1, "start sends SessionSetupReq (1 send)");
    CK(s->last_req == 1000, "start arms resp-wait anchor");
}

static void test_sequence_walk(void)
{
    uint8_t b[128]; uint16_t n; uint32_t now = 1000;
    reset(now);
    const din_session_t *s = din_session_get();

    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);          /* SessionSetupRes (ev0 [?]) */
    CK(s->state == DIN_ST_SERVICEDISCOVERY_RES, "2->3 on SessionSetupRes OK");
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);          /* ServiceDiscoveryRes */
    CK(s->state == DIN_ST_CPD_RES, "3->6 on ServiceDiscoveryRes (DIN skips 4/5)");
    n = mk_rc(b, 0); din_session_rx(EXI_EV_DC_EVSE_CHARGE_PARAM, b, n, now);  /* CPD Res */
    CK(s->state == DIN_ST_CABLECHECK_RES && s->chgparam_ok == 1, "6->7 on CPD Res + chgparam_ok");
    n = mk_cablecheck(b, 0, 1, 0); din_session_rx(EXI_EV_CABLECHECK_RES, b, n, now);
    CK(s->state == DIN_ST_PRECHARGE_RES && s->cablecheck_fin == 1 && s->precharge_flag == 1,
       "7->8 on CableCheck isolation==1 + cablecheck_fin + precharge_flag");
    n = mk_precharge(b, 0, 400); din_session_rx(EXI_EV_PRECHARGE_RES, b, n, now);
    CK(s->state == DIN_ST_POWERDELIVERY_START && s->precharge_relay == 1,
       "8->9 on PreChargeRes + precharge_relay");
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);          /* PowerDeliveryRes (start) */
    CK(s->state == DIN_ST_CURRENTDEMAND_RES && s->ev_contactor == 1,
       "9->10 on PowerDeliveryRes + ev_contactor");
    n = mk_cd_res(b, 0, 400, 100); din_session_rx(EXI_EV_CURRENTDEMAND_RES, b, n, now);
    CK(s->state == DIN_ST_CURRENTDEMAND_RES, "stay 10 on CurrentDemandRes (charging loop)");
    CK(din70121_meas()->evse_present_voltage == 400 && din70121_meas()->evse_max_current == 200,
       "CurrentDemandRes meas decoded (presentV=400, maxI=200)");

    /* stop -> 10->11->12->13->0 */
    din_session_stop(now);
    CK(s->state == DIN_ST_POWERDELIVERY_STOP && s->charging_complete == 1, "stop -> 11 + complete");
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);          /* PowerDeliveryRes (stop) */
    CK(s->state == DIN_ST_WELDING_RES, "11->12 on PowerDeliveryRes(stop)");
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);          /* WeldingDetectionRes */
    CK(s->state == DIN_ST_SESSIONSTOP_RES, "12->13 on WeldingDetectionRes");
    n = mk_sessionstop(b); din_session_rx(EXI_EV_SESSIONSTOP, b, n, now);
    CK(s->state == DIN_ST_IDLE && s->session_active == 0, "13->0 on SessionStopRes (reset)");
    CK(s->cablecheck_fin == 0 && s->ev_contactor == 0, "reset clears handshake flags");
}

static void test_resp_wait_retry(void)
{
    uint32_t now = 1000;
    reset(now);
    const din_session_t *s = din_session_get();
    tx_count = 0;
    /* resp-wait 4000 ms: step at +4001 -> retry 1 + re-send */
    din_session_step(now + 4001);
    CK(s->retry == 1, "resp-wait timeout -> retry 1");
    CK(tx_count == 1, "resp-wait timeout re-sends Req");
    CK(s->state == DIN_ST_SESSIONSETUP_RES, "resp-wait timeout stays in state");
    /* a valid Res resets retry */
    uint8_t b[16]; uint16_t n = mk_rc(b, 0);
    din_session_rx(0x00, b, n, now + 4002);
    CK(s->retry == 0, "valid Res resets retry counter");
}

static void test_retry_cap(void)
{
    uint32_t now = 1000;
    reset(now);
    const din_session_t *s = din_session_get();
    /* 21 resp-wait timeouts (cap 20) -> fault RETRY(1) + shutdown */
    for (int i = 1; i <= 21; i++) din_session_step(now + (uint32_t)i * 4001u);
    CK(s->fault_code == DIN_FAULT_RETRY && s->fault_flag == 1, "retry cap 20 -> fault code 1 + flag");
    CK(s->state == DIN_ST_POWERDELIVERY_STOP, "retry cap -> shutdown (PowerDelivery-stop)");
}

static void test_total_timeout(void)
{
    uint32_t now = 1000;
    reset(now);
    const din_session_t *s = din_session_get();
    /* keep re-arming resp-wait so only the total timer fires; step past t_total */
    din_session_step(now + 120001u);
    CK(s->fault_code == DIN_FAULT_TIMEOUT, "total timeout -> fault code 2");
    CK(s->state == DIN_ST_POWERDELIVERY_STOP, "total timeout -> shutdown");
}

static void test_cd_cadence(void)
{
    uint8_t b[128]; uint16_t n; uint32_t now = 1000;
    reset(now);
    const din_session_t *s = din_session_get();
    /* walk to state 10 */
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_rc(b, 0); din_session_rx(EXI_EV_DC_EVSE_CHARGE_PARAM, b, n, now);
    n = mk_cablecheck(b, 0, 1, 0); din_session_rx(EXI_EV_CABLECHECK_RES, b, n, now);
    n = mk_precharge(b, 0, 400); din_session_rx(EXI_EV_PRECHARGE_RES, b, n, now);
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    CK(s->state == DIN_ST_CURRENTDEMAND_RES, "walked to state 10 for cadence test");
    din_session_set_fp(10);
    tx_count = 0;
    /* step 10 ticks: tick_counter 1..10, modulo 10 == 0 at tick 10 -> 1 CDReq send */
    for (int i = 1; i <= 10; i++) din_session_step(now + (uint32_t)i);
    CK(tx_count == 1, "CD modulo cadence fp=10: 1 send per 10 ticks");
    CK(s->tick_counter == 10, "CD tick_counter advanced to 10");
    tx_count = 0;
    for (int i = 11; i <= 30; i++) din_session_step(now + (uint32_t)i);
    CK(tx_count == 2, "CD cadence: 2 more sends over ticks 11..30 (at 20,30)");
}

static void test_cablecheck_isolation(void)
{
    uint8_t b[64]; uint16_t n; uint32_t now = 1000;
    /* isolation == 0 -> retry (stay 7) */
    reset(now);
    const din_session_t *s = din_session_get();
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_rc(b, 0); din_session_rx(EXI_EV_DC_EVSE_CHARGE_PARAM, b, n, now);
    n = mk_cablecheck(b, 0, 0, 0); din_session_rx(EXI_EV_CABLECHECK_RES, b, n, now);
    CK(s->state == DIN_ST_CABLECHECK_RES && s->cablecheck_fin == 0,
       "CableCheck isolation==0 -> retry stay 7");
    /* isolation >= 2 -> fault ISOLATION(16) + shutdown */
    reset(now);
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_rc(b, 0); din_session_rx(EXI_EV_DC_EVSE_CHARGE_PARAM, b, n, now);
    n = mk_cablecheck(b, 0, 2, 0); din_session_rx(EXI_EV_CABLECHECK_RES, b, n, now);
    CK(s->fault_code == DIN_FAULT_ISOLATION, "CableCheck isolation>=2 -> fault code 16");
    CK(s->state == DIN_ST_POWERDELIVERY_STOP, "CableCheck fault -> shutdown");
    /* processing ongoing (proc==1) -> re-send stay 7 even with isolation valid */
    reset(now);
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_rc(b, 0); din_session_rx(EXI_EV_DC_EVSE_CHARGE_PARAM, b, n, now);
    tx_count = 0;
    n = mk_cablecheck(b, 0, 1, 1); din_session_rx(EXI_EV_CABLECHECK_RES, b, n, now);
    CK(s->state == DIN_ST_CABLECHECK_RES && tx_count == 1,
       "CableCheck processing ongoing -> re-send stay 7");
}

static void test_failed_response(void)
{
    uint8_t b[64]; uint16_t n; uint32_t now = 1000;
    reset(now);
    const din_session_t *s = din_session_get();
    /* FAILED ResponseCode (rc=3 FAILED) on SessionSetupRes -> fault RESPONSE(40) + shutdown */
    n = mk_rc(b, 3); din_session_rx(0x00, b, n, now);
    CK(s->fault_code == DIN_FAULT_RESPONSE, "FAILED ResponseCode -> fault code 40");
    CK(s->state == DIN_ST_POWERDELIVERY_STOP, "FAILED ResponseCode -> shutdown");
}

static void test_inert_no_fault_on_success(void)
{
    uint8_t b[128]; uint16_t n; uint32_t now = 1000;
    reset(now);
    const din_session_t *s = din_session_get();
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_rc(b, 0); din_session_rx(EXI_EV_DC_EVSE_CHARGE_PARAM, b, n, now);
    n = mk_cablecheck(b, 0, 1, 0); din_session_rx(EXI_EV_CABLECHECK_RES, b, n, now);
    n = mk_precharge(b, 0, 400); din_session_rx(EXI_EV_PRECHARGE_RES, b, n, now);
    n = mk_rc(b, 0); din_session_rx(0x00, b, n, now);
    n = mk_cd_res(b, 0, 400, 100); din_session_rx(EXI_EV_CURRENTDEMAND_RES, b, n, now);
    CK(s->fault_code == DIN_FAULT_NONE && s->fault_flag == 0,
       "successful sequence posts NO fault (inert, power drive gated)");
}

int main(void)
{
    test_init_start();
    test_sequence_walk();
    test_resp_wait_retry();
    test_retry_cap();
    test_total_timeout();
    test_cd_cadence();
    test_cablecheck_isolation();
    test_failed_response();
    test_inert_no_fault_on_success();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}