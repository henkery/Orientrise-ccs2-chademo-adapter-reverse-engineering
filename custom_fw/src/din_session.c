/* din_session.c — DIN70121 autonomous EVCC session state machine (REPORT §5.9, Agent F / analyze93).
 * Faithful INERT replica of the C013 distributed session SM (verify_f.py 28/28). RX transition
 * engine 0x080353B2 (advances on valid Res) + poll task 0x08038192 (timer/retry/re-send). Timers
 * from ctx init 0x08035198 (4000/120000/150000/40000/14000 ms), retry cap 20 (meas[0x244] cmp
 * #0x14), CD modulo cadence (meas[0xC] % fp), FAILED->SessionStop + fault post 0x0802C9D0 ->
 * 0x20000774. INERT: records the fault code + handshake flags, drives NO power GPIO; Req EXI images
 * produced via a TX hook (live send GATED). No libc mem* (loops). Host-tested (test_din_session.c).
 */
#include "din_session.h"
#include "din70121.h"
#include "exi.h"

/* Req root events (separate productions from the Res evs; E §3 encoder root). The application->ev
 * linkage / exact Req numbering is [?] (encoder side not fully recovered); symbolic placeholders
 * used by the inert replica. The SM sequence/timer logic is independent of these values. */
#define DIN_EV_SESSIONSETUP_REQ     0x01u   /* [?] */
#define DIN_EV_SERVICEDISCOVERY_REQ 0x03u   /* [?] */
#define DIN_EV_CPD_REQ              0x07u   /* [?] */
#define DIN_EV_CABLECHECK_REQ       0x09u   /* [?] */
#define DIN_EV_PRECHARGE_REQ        0x0Bu   /* [?] */
#define DIN_EV_POWERDELIVERY_REQ    0x0Du   /* [?] */
#define DIN_EV_CURRENTDEMAND_REQ    0x0Fu   /* [?] */
#define DIN_EV_WELDING_REQ          0x11u   /* [?] */
#define DIN_EV_SESSIONSTOP_REQ      0x13u   /* [?] */

static din_session_t sess;
static din_session_tx_fn tx_hook;
static uint8_t req_buf[256];

static void z(uint8_t *p, uint16_t n) { for (uint16_t i = 0; i < n; i++) p[i] = 0; }

/* Default TX hook: produce the inert EXI Req image. CurrentDemandReq uses the grammar encoder
 * (din_cd_req_encode_exi); the other Req grammars are partial (E §3) so a minimal framing image
 * (8-byte V2GTP reserved + leading 0x80 + 7-bit event) is produced [? body]. Live send is GATED. */
static int default_tx(uint8_t ev, uint8_t *buf, uint16_t cap)
{
    if (ev == DIN_EV_CURRENTDEMAND_REQ)
        return din_cd_req_encode_exi(din70121_meas_mut(), buf, cap, ev);
    exi_stream_t s;
    exi_encode_init(&s, buf, cap, EXI_V2GTP_HDR_LEN);
    int r = exi_encode_header(&s, ev);
    if (r < 0) return r;
    return (int)exi_encode_finish(&s);
}

void din_session_init(void)
{
    z((uint8_t *)&sess, sizeof sess);
    sess.resp_wait = DIN_RESP_WAIT_MS;
    sess.t_total   = DIN_T_TOTAL_MS;
    sess.t_150     = DIN_T_150_MS;
    sess.t_40      = DIN_T_40_MS;
    sess.t_14      = DIN_T_14_MS;
    sess.fp        = DIN_CD_FP_DEFAULT;
    sess.state     = DIN_ST_IDLE;
    tx_hook        = default_tx;
}

void din_session_set_tx(din_session_tx_fn fn) { tx_hook = fn ? fn : default_tx; }
void din_session_set_fp(uint16_t fp) { sess.fp = fp; }

/* Send the Req for the current state; re-arm the resp-wait anchor (ctx+4 re-armed every send). */
static void send_req(uint8_t ev, uint32_t now)
{
    sess.last_req = now;
    sess.req_ev = ev;
    int n = tx_hook ? tx_hook(ev, req_buf, sizeof req_buf) : 0;
    sess.req_len = (n > 0) ? (uint16_t)n : 0u;
}

/* Req event awaited->sent mapping for re-send on resp-wait timeout. */
static uint8_t req_ev_for_state(uint8_t st)
{
    switch (st) {
    case DIN_ST_SESSIONSETUP_RES:     return DIN_EV_SESSIONSETUP_REQ;
    case DIN_ST_SERVICEDISCOVERY_RES: return DIN_EV_SERVICEDISCOVERY_REQ;
    case DIN_ST_CPD_RES:              return DIN_EV_CPD_REQ;
    case DIN_ST_CABLECHECK_RES:       return DIN_EV_CABLECHECK_REQ;
    case DIN_ST_PRECHARGE_RES:        return DIN_EV_PRECHARGE_REQ;
    case DIN_ST_POWERDELIVERY_START:  return DIN_EV_POWERDELIVERY_REQ;
    case DIN_ST_CURRENTDEMAND_RES:    return DIN_EV_CURRENTDEMAND_REQ;
    case DIN_ST_POWERDELIVERY_STOP:   return DIN_EV_POWERDELIVERY_REQ;
    case DIN_ST_WELDING_RES:          return DIN_EV_WELDING_REQ;
    case DIN_ST_SESSIONSTOP_RES:      return DIN_EV_SESSIONSTOP_REQ;
    default:                          return DIN_EV_SESSIONSETUP_REQ;
    }
}

/* Fault setter 0x0802C9D0: post code to 0x20000774 (inert: record only, no GPIO). */
static void post_fault(uint8_t code)
{
    sess.fault_code = code;
    sess.fault_flag = 1;
    sess.phase_status = 7;   /* error setters 0x0802BA6C/80/94/A8 -> meas+0x3D1E=7 (analyze103) */
}

/* Graceful shutdown: PowerDelivery-stop -> SessionStop -> state 13 (F §FAILED->shutdown). */
static void shutdown_seq(uint32_t now)
{
    send_req(DIN_EV_POWERDELIVERY_REQ, now);   /* PowerDelivery-stop 0x08034A78 */
    sess.state = DIN_ST_POWERDELIVERY_STOP;
}

void din_session_start(uint32_t now)
{
    if (sess.session_active) return;
    sess.session_active = 1;
    sess.ts_total = now; sess.ts_150 = now; sess.ts_40 = now; sess.ts_14 = now;
    sess.retry = 0; sess.fault_code = DIN_FAULT_NONE; sess.fault_flag = 0;
    sess.charging_complete = 0;
    sess.state = DIN_ST_PRE_SETUP;
    send_req(DIN_EV_SESSIONSETUP_REQ, now);    /* state 1 -> SessionSetupReq */
    sess.state = DIN_ST_SESSIONSETUP_RES;      /* state 2 await Res */
}

/* Poll task 0x08038192: timer/retry/re-send engine (never advances state on success). */
void din_session_step(uint32_t now)
{
    if (!sess.session_active || sess.state == DIN_ST_IDLE) return;

    /* Session-GLOBAL total timeouts: ctx+8=120s (f_24 compare 0x08038458/0x0803874E, gate
     * ctx+0x2A ~ session_active) and ctx+C=150s (clean cmp not found [?]; outer guard, never
     * fires before 120s). The 40s/14s timers are engagement-phase (f_27, below) — they must NOT
     * preempt the per-message resp-wait/retry loop in the early handshake states (F §2.2/2.3). */
    if ((uint32_t)(now - sess.ts_total) > sess.t_total ||
        (uint32_t)(now - sess.ts_150)   > sess.t_150) {
        post_fault(DIN_FAULT_TIMEOUT);
        shutdown_seq(now);
        return;
    }

    /* Resp-wait timeout (ctx+4 = 4000 ms, re-armed every send): retry / re-send / fault. This is
     * the universal per-message engine (F §2.1, every awaited Res SessionSetup..SessionStop). */
    if (sess.state >= DIN_ST_SESSIONSETUP_RES && sess.state <= DIN_ST_SESSIONSTOP_RES) {
        if ((uint32_t)(now - sess.last_req) > sess.resp_wait) {
            sess.retry++;                         /* meas[0x244]++ */
            if (sess.retry > DIN_RETRY_CAP) {     /* cmp #0x14 (20) */
                post_fault(DIN_FAULT_RETRY);      /* meas[0x248]=1 + fault code 1 */
                shutdown_seq(now);
                return;
            }
            send_req(req_ev_for_state(sess.state), now);   /* re-send, stay in state */
        }
    }

    /* Engagement/charging-PHASE timers: ctx+0x10=40s (compare 0x08039002) and ctx+0x12=14s
     * (compare 0x0803940E), both in the f_27 CurrentDemand/engagement poll region (0x08039xxx,
     * clustered with the CD cadence 0x080396F6). Gated to the power phases (state >= CableCheck)
     * [? exact phase gate not pinned]; anchors re-armed on CableCheck entry [? re-arm site]. */
    if (sess.state >= DIN_ST_CABLECHECK_RES &&
        ((uint32_t)(now - sess.ts_40) > sess.t_40 ||
         (uint32_t)(now - sess.ts_14) > sess.t_14)) {
        post_fault(DIN_FAULT_TIMEOUT);
        shutdown_seq(now);
        return;
    }

    /* CurrentDemand re-send cadence (state 10). PRIMARY: meas[0xC] % fp == 0 (udiv/mls @0x080396F6).
     * SECONDARY: ctx+0x44 interval gated ctx+0x46==1 (@0x08039698), parameterized. */
    if (sess.state == DIN_ST_CURRENTDEMAND_RES) {
        sess.tick_counter++;                      /* meas[0xC] u8 wraps 200 */
        if (sess.tick_counter >= 200u) sess.tick_counter = 0;
        if (sess.fp && (sess.tick_counter % sess.fp) == 0u)
            send_req(DIN_EV_CURRENTDEMAND_REQ, now);
        if (sess.cd_resend_active && sess.cd_interval &&
            (uint32_t)(now - sess.ts_cd) > sess.cd_interval) {
            send_req(DIN_EV_CURRENTDEMAND_REQ, now);
            sess.ts_cd = now;
        }
    }
}

/* Read the 5-bit ResponseCode (first field of every DIN Res). OK=0/1/2 advance; else FAILED. */
static int read_rc(const uint8_t *body, uint16_t len, uint8_t *rc)
{
    exi_stream_t s;
    exi_decode_init(&s, body, len);
    uint32_t v;
    int r = exi_read_bits(&s, 5, &v);
    if (r) return r;
    *rc = (uint8_t)v;
    return EXI_OK;
}
static int rc_ok(uint8_t rc) { return rc <= 2u; }   /* OK / OK_NewSessionEstablished */

/* RX transition engine 0x080353B2: decode a Res and advance state on success. */
int din_session_rx(uint8_t ev, const uint8_t *body, uint16_t len, uint32_t now)
{
    if (!sess.session_active) return EXI_ERR_EVENT;
    uint8_t rc = 0;
    int r;

    switch (ev) {
    case EXI_EV_SESSIONSTOP:                       /* SessionStopRes (empty) -> reset */
        r = din_sessionstop_res_decode_exi(body, len);
        if (r) return r;
        sess.session_active = 0;
        sess.state = DIN_ST_IDLE;
        sess.cablecheck_fin = sess.chgparam_ok = sess.precharge_flag = 0;
        sess.ev_contactor = sess.precharge_relay = 0;
        return EXI_OK;

    case EXI_EV_CABLECHECK_RES: {
        uint8_t proc = 0;
        din_dc_evse_status_t st;
        r = din_cablecheck_res_decode_exi(body, len, &rc, &proc, &st);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.din_isolation = st.isolation_status;  /* DIN wire isolation (session CableCheck rule only) */
        sess.phase_status = 3;                     /* CableCheckRes writer 0x0802C168 -> meas+0x3D1E=3 */
        if (proc == 1u) {                          /* EVSEProcessingState ongoing -> re-send, stay 7 */
            send_req(DIN_EV_CABLECHECK_REQ, now);
            return EXI_OK;
        }
        if (st.isolation_status == 1u) {           /* Valid -> advance 7->8 (0x080366AE) */
            sess.cablecheck_fin = 1;
            sess.precharge_flag = 1;               /* evcc_sta+0x23F (case7 [r4+0x23F]=1) */
            sess.state = DIN_ST_PRECHARGE_RES;
            send_req(DIN_EV_PRECHARGE_REQ, now);
        } else if (st.isolation_status == 0u) {    /* invalid -> retry / SessionStop */
            send_req(DIN_EV_CABLECHECK_REQ, now);
        } else {                                   /* >=2 -> fault code 16 shutdown */
            post_fault(DIN_FAULT_ISOLATION);
            shutdown_seq(now);
        }
        return EXI_OK;
    }

    case EXI_EV_PRECHARGE_RES: {
        din_dc_evse_status_t st;
        r = din_precharge_res_decode_exi(body, len, din70121_meas_mut(), &rc, &st);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.phase_status = 4;                     /* PreChargeRes writer 0x0802C27A -> meas+0x3D1E=4
                                                    * (the charge_stm engagement prerequisite) */
        sess.precharge_relay = 1;
        sess.state = DIN_ST_POWERDELIVERY_START;   /* 8->9 */
        send_req(DIN_EV_POWERDELIVERY_REQ, now);   /* PowerDelivery-start */
        return EXI_OK;
    }

    case EXI_EV_CURRENTDEMAND_RES: {
        r = din_cd_res_decode_exi(body, len, din70121_meas_mut(), &rc);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.retry = 0;                            /* valid Res resets the retry counter */
        if (sess.charging_complete) {              /* stop requested -> 10->11 */
            sess.state = DIN_ST_POWERDELIVERY_STOP;
            send_req(DIN_EV_POWERDELIVERY_REQ, now);   /* PowerDelivery-stop */
        }
        /* else stay in state 10 (charging loop); re-send driven by the poll cadence. */
        return EXI_OK;
    }

    case EXI_EV_DC_EVSE_CHARGE_PARAM:              /* CPD Res payload (charge parameter) */
        r = read_rc(body, len, &rc);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.chgparam_ok = 1;
        sess.ts_40 = now; sess.ts_14 = now;        /* engagement-phase timer anchors [? re-arm site] */
        sess.state = DIN_ST_CABLECHECK_RES;        /* 6->7 */
        send_req(DIN_EV_CABLECHECK_REQ, now);
        return EXI_OK;

    default:
        /* SessionSetupRes / ServiceDiscoveryRes / PowerDeliveryRes / WeldingDetectionRes: full
         * field lists partial (E §3); read the ResponseCode (first 5-bit field) to advance. */
        r = read_rc(body, len, &rc);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.retry = 0;
        switch (sess.state) {
        case DIN_ST_SESSIONSETUP_RES:              /* 2->3 */
            sess.state = DIN_ST_SERVICEDISCOVERY_RES;
            send_req(DIN_EV_SERVICEDISCOVERY_REQ, now);
            break;
        case DIN_ST_SERVICEDISCOVERY_RES:          /* 3->6 (DIN skips PaymentSelection/ContractAuth 4/5 [?]) */
            sess.state = DIN_ST_CPD_RES;
            send_req(DIN_EV_CPD_REQ, now);
            break;
        case DIN_ST_POWERDELIVERY_START:           /* 9->10 */
            sess.ev_contactor = 1;
            sess.state = DIN_ST_CURRENTDEMAND_RES;
            sess.ts_cd = now;
            sess.tick_counter = 0;
            send_req(DIN_EV_CURRENTDEMAND_REQ, now);
            break;
        case DIN_ST_POWERDELIVERY_STOP:            /* 11->12 */
            sess.state = DIN_ST_WELDING_RES;
            send_req(DIN_EV_WELDING_REQ, now);
            break;
        case DIN_ST_WELDING_RES:                   /* 12->13 */
            sess.state = DIN_ST_SESSIONSTOP_RES;
            send_req(DIN_EV_SESSIONSTOP_REQ, now);
            break;
        default:
            return EXI_ERR_EVENT;
        }
        return EXI_OK;
    }
}

void din_session_stop(uint32_t now)
{
    if (!sess.session_active) return;
    sess.charging_complete = 1;
    if (sess.state == DIN_ST_CURRENTDEMAND_RES) {
        sess.state = DIN_ST_POWERDELIVERY_STOP;
        send_req(DIN_EV_POWERDELIVERY_REQ, now);
    }
}

const din_session_t *din_session_get(void) { return &sess; }
uint8_t din_session_fault(void) { return sess.fault_code; }