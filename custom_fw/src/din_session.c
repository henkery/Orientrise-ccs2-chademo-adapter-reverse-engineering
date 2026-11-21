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

/* B2 DIN document model (analyze101/102): every Req rides the SINGLE root 0x4D + DIN header + a
 * 6-bit message choice (exi.h DIN_REQ_*); every Res a 6-bit subev (DIN_RES_*). The old per-message
 * "root events" were production grammar-ids misused as roots — removed. The TX hook's `ev` arg is
 * now the DIN_REQ_* choice; the RX `ev` arg is the DIN_RES_* subev. The SM sequence/timer logic is
 * unchanged. Req bodies are produced by the B2 din70121.c encoders (full document framing). */

static din_session_t sess;
static din_session_tx_fn tx_hook;
static uint8_t req_buf[256];

static void z(uint8_t *p, uint16_t n) { for (uint16_t i = 0; i < n; i++) p[i] = 0; }

/* Default TX hook: produce the inert DIN Req document for message choice `ev` (DIN_REQ_*). Each
 * encoder writes the full framing (8-byte V2GTP reserved + 0x80 + root 0x4D + DIN header + choice
 * + body + EE gate) using the session SessionID/EVCCID. Live send is GATED. */
static int default_tx(uint8_t ev, uint8_t *buf, uint16_t cap)
{
    const uint8_t *sid = sess.sid;
    uint16_t sid_len = sess.sid_len;
    switch (ev) {
    case DIN_REQ_SESSIONSETUP:
        return din_sessionsetup_req_encode(buf, cap, sid, sid_len, sess.evccid, sess.evccid_len);
    case DIN_REQ_SERVICEDISCOVERY:
        return din_servicediscovery_req_encode(buf, cap, sid, sid_len);
    case DIN_REQ_CPD:
        return din_cpd_req_encode(buf, cap, sid, sid_len, din70121_meas(), 1u, 70u);
    case DIN_REQ_CABLECHECK:
        return din_cablecheck_req_encode(buf, cap, sid, sid_len, 1u, 70u);
    case DIN_REQ_PRECHARGE:
        return din_precharge_req_encode(buf, cap, sid, sid_len, din70121_meas(), 1u, 70u);
    case DIN_REQ_POWERDELIVERY:
        return din_powerdelivery_req_encode(buf, cap, sid, sid_len, sess.charge_progress);
    case DIN_REQ_CURRENTDEMAND:
        return din_cd_req_encode_exi(din70121_meas_mut(), buf, cap, sid, sid_len);
    case DIN_REQ_WELDING:
        return din_welding_req_encode(buf, cap, sid, sid_len, 1u, 70u);
    case DIN_REQ_SESSIONSTOP:
        return din_sessionstop_req_encode(buf, cap, sid, sid_len);
    default:
        return EXI_ERR_EVENT;
    }
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
    sess.sid[0]    = 0x00u;        /* SessionSetupReq builder SID placeholder (1 byte) */
    sess.sid_len   = 1u;
    sess.evccid_len = 6u;          /* EVCCID = 6-byte unit MAC (zeros until ccs2 sets it) */
    tx_hook        = default_tx;
}

void din_session_set_tx(din_session_tx_fn fn) { tx_hook = fn ? fn : default_tx; }
void din_session_set_fp(uint16_t fp) { sess.fp = fp; }
void din_session_set_evccid(const uint8_t *id, uint16_t len)
{
    if (len > 6u) len = 6u;
    for (uint16_t i = 0; i < len; i++) sess.evccid[i] = id[i];
    sess.evccid_len = len;
}

static void send_req(uint8_t ev, uint32_t now);

/* PowerDelivery send helper: set ChargeProgress (0=Start / 1=Stop) then emit the Req choice. */
static void send_powerdelivery(uint8_t progress, uint32_t now)
{
    sess.charge_progress = progress;
    send_req(DIN_REQ_POWERDELIVERY, now);
}

/* Send the Req for the current state; re-arm the resp-wait anchor (ctx+4 re-armed every send). */
static void send_req(uint8_t ev, uint32_t now)
{
    sess.last_req = now;
    sess.req_ev = ev;
    int n = tx_hook ? tx_hook(ev, req_buf, sizeof req_buf) : 0;
    sess.req_len = (n > 0) ? (uint16_t)n : 0u;
}

/* Req choice awaited->sent mapping for re-send on resp-wait timeout (DIN_REQ_* choices). */
static uint8_t req_ev_for_state(uint8_t st)
{
    switch (st) {
    case DIN_ST_SESSIONSETUP_RES:     return DIN_REQ_SESSIONSETUP;
    case DIN_ST_SERVICEDISCOVERY_RES: return DIN_REQ_SERVICEDISCOVERY;
    case DIN_ST_CPD_RES:              return DIN_REQ_CPD;
    case DIN_ST_CABLECHECK_RES:       return DIN_REQ_CABLECHECK;
    case DIN_ST_PRECHARGE_RES:        return DIN_REQ_PRECHARGE;
    case DIN_ST_POWERDELIVERY_START:  return DIN_REQ_POWERDELIVERY;
    case DIN_ST_CURRENTDEMAND_RES:    return DIN_REQ_CURRENTDEMAND;
    case DIN_ST_POWERDELIVERY_STOP:   return DIN_REQ_POWERDELIVERY;
    case DIN_ST_WELDING_RES:          return DIN_REQ_WELDING;
    case DIN_ST_SESSIONSTOP_RES:      return DIN_REQ_SESSIONSTOP;
    default:                          return DIN_REQ_SESSIONSETUP;
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
    send_powerdelivery(1u, now);               /* PowerDelivery-stop 0x08034A78 (ChargeProgress=1) */
    sess.state = DIN_ST_POWERDELIVERY_STOP;
}

void din_session_start(uint32_t now)
{
    if (sess.session_active) return;
    sess.session_active = 1;
    sess.ts_total = now; sess.ts_150 = now; sess.ts_40 = now; sess.ts_14 = now;
    sess.retry = 0; sess.fault_code = DIN_FAULT_NONE; sess.fault_flag = 0;
    sess.charging_complete = 0;
    sess.charge_progress = 0;
    sess.state = DIN_ST_PRE_SETUP;
    send_req(DIN_REQ_SESSIONSETUP, now);       /* state 1 -> SessionSetupReq */
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
            send_req(DIN_REQ_CURRENTDEMAND, now);
        if (sess.cd_resend_active && sess.cd_interval &&
            (uint32_t)(now - sess.ts_cd) > sess.cd_interval) {
            send_req(DIN_REQ_CURRENTDEMAND, now);
            sess.ts_cd = now;
        }
    }
}

static int rc_ok(uint8_t rc) { return rc <= 2u; }   /* OK / OK_NewSessionEstablished */

/* RX transition engine 0x080353B2: decode a Res (DIN_RES_* subev + EXI body) and advance state on
 * success. The body has the DIN document framing stripped by ccs2_rx_exi (exi_decode_header +
 * exi_din_decode_doc_start); each decoder reads its recovered field list (analyze102). */
int din_session_rx(uint8_t ev, const uint8_t *body, uint16_t len, uint32_t now)
{
    if (!sess.session_active) return EXI_ERR_EVENT;
    uint8_t rc = 0;
    int r;

    switch (ev) {
    case DIN_RES_SESSIONSTOP:                      /* SessionStopRes (empty) -> reset */
        r = din_sessionstop_res_decode_exi(body, len);
        if (r) return r;
        sess.session_active = 0;
        sess.state = DIN_ST_IDLE;
        sess.cablecheck_fin = sess.chgparam_ok = sess.precharge_flag = 0;
        sess.ev_contactor = sess.precharge_relay = 0;
        return EXI_OK;

    case DIN_RES_SESSIONSETUP: {                   /* SessionSetupRes ev41 -> 2->3 */
        uint8_t evseid[32]; uint16_t evseid_len = 0;
        r = din_sessionsetup_res_decode_exi(body, len, &rc, evseid, &evseid_len);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.retry = 0;
        sess.state = DIN_ST_SERVICEDISCOVERY_RES;  /* 2->3 */
        send_req(DIN_REQ_SERVICEDISCOVERY, now);
        return EXI_OK;
    }

    case DIN_RES_SERVICEDISCOVERY:                 /* ServiceDiscoveryRes ev3d -> 3->6 */
        r = din_servicediscovery_res_decode_exi(body, len, &rc);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.retry = 0;
        sess.state = DIN_ST_CPD_RES;               /* 3->6 (DIN skips PaymentSelection/ContractAuth 4/5) */
        send_req(DIN_REQ_CPD, now);
        return EXI_OK;

    case DIN_RES_CPD: {                            /* CPDRes ev0c -> 6->7 (DCparam limits -> meas) */
        uint8_t proc = 0;
        din_dc_charge_param_t param;
        r = din_cpd_res_decode_exi(body, len, &rc, &proc, &param);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        if (proc == 1u) {                          /* EVSEProcessing ongoing -> re-send, stay 6 */
            send_req(DIN_REQ_CPD, now);
            return EXI_OK;
        }
        din_meas_t *m = din70121_meas_mut();       /* apply the EVSE DC limits (factor = mult+3) */
        m->evse_max_current   = param.max_current.value;
        m->evse_max_current_f = (int8_t)(param.max_current.mult + 3);
        m->evse_max_voltage   = param.max_voltage.value;
        m->evse_max_voltage_f = (int8_t)(param.max_voltage.mult + 3);
        sess.chgparam_ok = 1;
        sess.ts_40 = now; sess.ts_14 = now;        /* engagement-phase timer anchors [? re-arm site] */
        sess.state = DIN_ST_CABLECHECK_RES;        /* 6->7 */
        send_req(DIN_REQ_CABLECHECK, now);
        return EXI_OK;
    }

    case DIN_RES_CABLECHECK: {
        uint8_t proc = 0;
        din_dc_evse_status_t st;
        r = din_cablecheck_res_decode_exi(body, len, &rc, &proc, &st);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.din_isolation = st.isolation_status;  /* DIN wire isolation (session CableCheck rule only) */
        sess.phase_status = 3;                     /* CableCheckRes writer 0x0802C168 -> meas+0x3D1E=3 */
        if (proc == 1u) {                          /* EVSEProcessingState ongoing -> re-send, stay 7 */
            send_req(DIN_REQ_CABLECHECK, now);
            return EXI_OK;
        }
        if (st.isolation_status == 1u) {           /* Valid -> advance 7->8 (0x080366AE) */
            sess.cablecheck_fin = 1;
            sess.precharge_flag = 1;               /* evcc_sta+0x23F (case7 [r4+0x23F]=1) */
            sess.state = DIN_ST_PRECHARGE_RES;
            send_req(DIN_REQ_PRECHARGE, now);
        } else if (st.isolation_status == 0u) {    /* invalid -> retry / SessionStop */
            send_req(DIN_REQ_CABLECHECK, now);
        } else {                                   /* >=2 -> fault code 16 shutdown */
            post_fault(DIN_FAULT_ISOLATION);
            shutdown_seq(now);
        }
        return EXI_OK;
    }

    case DIN_RES_PRECHARGE: {
        din_dc_evse_status_t st;
        r = din_precharge_res_decode_exi(body, len, din70121_meas_mut(), &rc, &st);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.phase_status = 4;                     /* PreChargeRes writer 0x0802C27A -> meas+0x3D1E=4
                                                    * (the charge_stm engagement prerequisite) */
        sess.precharge_relay = 1;
        sess.state = DIN_ST_POWERDELIVERY_START;   /* 8->9 */
        send_powerdelivery(0u, now);               /* PowerDelivery-start (ChargeProgress=0) */
        return EXI_OK;
    }

    case DIN_RES_POWERDELIVERY: {                  /* PowerDeliveryRes ev2e -> 9->10 or 11->12 */
        din_dc_evse_status_t st;
        r = din_powerdelivery_res_decode_exi(body, len, &rc, &st);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.retry = 0;
        if (sess.state == DIN_ST_POWERDELIVERY_START) {   /* 9->10 */
            sess.ev_contactor = 1;
            sess.state = DIN_ST_CURRENTDEMAND_RES;
            sess.ts_cd = now;
            sess.tick_counter = 0;
            send_req(DIN_REQ_CURRENTDEMAND, now);
        } else if (sess.state == DIN_ST_POWERDELIVERY_STOP) {  /* 11->12 */
            sess.state = DIN_ST_WELDING_RES;
            send_req(DIN_REQ_WELDING, now);
        } else {
            return EXI_ERR_EVENT;
        }
        return EXI_OK;
    }

    case DIN_RES_CURRENTDEMAND: {
        r = din_cd_res_decode_exi(body, len, din70121_meas_mut(), &rc);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.retry = 0;                            /* valid Res resets the retry counter */
        if (sess.charging_complete) {              /* stop requested -> 10->11 */
            sess.state = DIN_ST_POWERDELIVERY_STOP;
            send_powerdelivery(1u, now);           /* PowerDelivery-stop (ChargeProgress=1) */
        }
        /* else stay in state 10 (charging loop); re-send driven by the poll cadence. */
        return EXI_OK;
    }

    case DIN_RES_WELDING: {                        /* WeldingDetectionRes ev4f -> 12->13 */
        din_dc_evse_status_t st;
        r = din_welding_res_decode_exi(body, len, din70121_meas_mut(), &rc, &st);
        if (r) return r;
        if (!rc_ok(rc)) { post_fault(DIN_FAULT_RESPONSE); shutdown_seq(now); return EXI_OK; }
        sess.retry = 0;
        sess.state = DIN_ST_SESSIONSTOP_RES;       /* 12->13 */
        send_req(DIN_REQ_SESSIONSTOP, now);
        return EXI_OK;
    }

    default:
        return EXI_ERR_EVENT;
    }
}

void din_session_stop(uint32_t now)
{
    if (!sess.session_active) return;
    sess.charging_complete = 1;
    if (sess.state == DIN_ST_CURRENTDEMAND_RES) {
        sess.state = DIN_ST_POWERDELIVERY_STOP;
        send_powerdelivery(1u, now);               /* PowerDelivery-stop (ChargeProgress=1) */
    }
}

const din_session_t *din_session_get(void) { return &sess; }
uint8_t din_session_fault(void) { return sess.fault_code; }