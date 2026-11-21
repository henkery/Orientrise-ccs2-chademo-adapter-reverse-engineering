/* din_session.h — DIN70121 autonomous EVCC session state machine (REPORT §5.9, Agent F / analyze93).
 *
 * Faithful INERT replica of the C013 distributed DIN session SM (the "session timers" GATED layer
 * recovered by Agent F, independently verified verify_f.py 28/28). The stock SM is split across an
 * RX handler 0x080353B2 (transition engine: advances state only on a valid Res) and a poll task
 * 0x08038192 (timer/retry/re-send engine: never advances on success), driven by an RTOS loop
 * 0x08039AF8 (~10 ms period) off a TIM7 1 ms tick (ISR 0x0808A198 -> [0x20000A54], PSC=83/ARR=999).
 *
 * State variable = session ctx 0x2000B3B0[0] (byte enum 0..13 = "which Res is awaited"), the first
 * field of a 0x48-byte ctx (= 0x2000B3F8 - 0x48). Dispatch tbh 0x08035444 (table 0x08035448, gate
 * cmp #0xe). Init 0x08035198 sets the timeout constants. This replica expresses the timers in ms
 * and adapts them to the app's 100 Hz tick (tick_get, 10 ms units) — the stock 1 ms TIM7 tick is
 * modeled by a ms argument to din_session_step.
 *
 * INERT: the SM evaluates the sequence + timers + interlocks and RECORDS the fault code each path
 * would post (stock fault setter 0x0802C9D0 -> 0x20000774, read by CHAdeMO to open the contactor),
 * but drives NO power GPIO. Req EXI images are produced via a TX hook (live TCP/TLS send GATED).
 * The asserted power drive stays the last gated layer (charge_stm engagement). See F_verified.md.
 */
#ifndef DIN_SESSION_H
#define DIN_SESSION_H
#include <stdint.h>

/* Session state enum 0..13 (state = which Res is awaited; F §state table). */
typedef enum {
    DIN_ST_IDLE = 0,            /* no session                                        */
    DIN_ST_PRE_SETUP,           /* 1 pre-setup -> SessionSetupReq                    */
    DIN_ST_SESSIONSETUP_RES,    /* 2 await SessionSetupRes                           */
    DIN_ST_SERVICEDISCOVERY_RES,/* 3 await ServiceDiscoveryRes                       */
    DIN_ST_PAYMENT_SEL_RES,     /* 4 [?] ISO ServicePaymentSelection (DIN skips)     */
    DIN_ST_CONTRACT_AUTH_RES,   /* 5 [?] ISO ContractAuthentication (DIN skips)      */
    DIN_ST_CPD_RES,             /* 6 await ChargeParameterDiscoveryRes               */
    DIN_ST_CABLECHECK_RES,      /* 7 await CableCheckRes                             */
    DIN_ST_PRECHARGE_RES,       /* 8 await PreChargeRes                              */
    DIN_ST_POWERDELIVERY_START, /* 9 await PowerDeliveryRes (start)                  */
    DIN_ST_CURRENTDEMAND_RES,   /* 10 await CurrentDemandRes (charging loop)         */
    DIN_ST_POWERDELIVERY_STOP,  /* 11 await PowerDeliveryRes (stop)                  */
    DIN_ST_WELDING_RES,         /* 12 await WeldingDetectionRes                      */
    DIN_ST_SESSIONSTOP_RES,     /* 13 await SessionStopRes                           */
    DIN_ST_COUNT
} din_state_t;

/* Timeout constants (ms) — session ctx init 0x08035198 (F §timers, verify_f confirmed). */
#define DIN_RESP_WAIT_MS     4000u    /* ctx+4 u16: resp-wait, re-armed every send       */
#define DIN_T_TOTAL_MS       120000u  /* ctx+8 u32: total session timeout                */
#define DIN_T_150_MS         150000u  /* ctx+C u32                                       */
#define DIN_T_40_MS          40000u   /* ctx+10 u16                                      */
#define DIN_T_14_MS          14000u   /* ctx+12 u16                                      */
#define DIN_RETRY_CAP        20u      /* meas[0x244]++ cmp #0x14 -> fault code 1         */
#define DIN_CD_FP_DEFAULT    10u      /* modulo divisor fp (runtime-negotiated; default) */

/* Fault codes posted to 0x20000774 (stock fault setter 0x0802C9D0; F §FAILED->shutdown). */
#define DIN_FAULT_NONE       0u
#define DIN_FAULT_RETRY      1u       /* retry cap exceeded                              */
#define DIN_FAULT_TIMEOUT    2u       /* resp-wait / total timeout                       */
#define DIN_FAULT_ISOLATION  16u      /* CableCheck isolation >= 2 (fault)               */
#define DIN_FAULT_RESPONSE   40u      /* ResponseCode FAILED                             */
#define DIN_FAULT_HARD       46u      /* hard fault (0x2e, case9 alt entry)              */

/* TX hook: encode + (gated) send a Req for root event `ev` into buf[cap]; returns length or <0.
 * The live network send is GATED; the default hook produces the inert EXI image only. */
typedef int (*din_session_tx_fn)(uint8_t ev, uint8_t *buf, uint16_t cap);

/* Session context (mirrors the stock 0x48-byte ctx + meas retry/cadence fields; F §ctx layout). */
typedef struct {
    uint8_t  state;             /* +0 din_state_t                                        */
    uint16_t resp_wait;         /* +4 = 4000                                             */
    uint32_t t_total;           /* +8 = 120000                                           */
    uint32_t t_150;             /* +C = 150000                                           */
    uint16_t t_40;              /* +10 = 40000                                           */
    uint16_t t_14;              /* +12 = 14000                                           */
    uint32_t last_req;          /* +14 tick of last Req send (resp-wait anchor)          */
    uint32_t ts_total;          /* +18 total-timeout anchor                              */
    uint32_t ts_150;            /* +1C                                                   */
    uint32_t ts_40;             /* +20                                                   */
    uint32_t ts_14;             /* +24                                                   */
    uint32_t ts_cd;             /* +40 CD/Welding re-send anchor                         */
    uint16_t cd_interval;       /* +44 secondary re-send interval (parameterized)        */
    uint8_t  cd_resend_active;  /* +46 secondary re-send arm                             */
    uint8_t  retry;             /* meas[0x244] retry counter (cap 20)                    */
    uint8_t  fault_flag;        /* meas[0x248]                                           */
    uint8_t  fault_code;        /* 0x20000774[0]                                         */
    uint16_t fp;                /* modulo divisor (runtime-negotiated; default 10)       */
    uint8_t  tick_counter;      /* meas[0xC] CD cadence counter (wraps 200)              */
    /* handshake outputs consumed by ccs2_evse -> charge_stm (F §sequence). */
    uint8_t  cablecheck_fin;
    uint8_t  chgparam_ok;
    uint8_t  precharge_flag;    /* evcc_sta+0x23F                                        */
    uint8_t  ev_contactor;
    uint8_t  precharge_relay;
    uint16_t isolation;         /* EVSEIsolationStatus (raw; 3/4 level mapping gated)    */
    uint8_t  session_active;
    uint8_t  charging_complete;
    /* last produced Req image (inert; SWD-readable). */
    uint8_t  req_ev;
    uint16_t req_len;
} din_session_t;

void din_session_init(void);
void din_session_set_tx(din_session_tx_fn fn);
void din_session_set_fp(uint16_t fp);          /* parameterize the runtime-negotiated divisor */
/* Begin a session (SDP done): state 1 -> SessionSetupReq -> state 2. */
void din_session_start(uint32_t now_ms);
/* Poll task 0x08038192: timer/retry/re-send engine (never advances on success). Call each tick. */
void din_session_step(uint32_t now_ms);
/* RX transition engine 0x080353B2: decode a Res (root event ev + EXI body) and advance state.
 * Returns EXI_OK on a valid transition, negative EXI error / DIN fault on failure. */
int din_session_rx(uint8_t ev, const uint8_t *body, uint16_t len, uint32_t now_ms);
/* Request a graceful stop (charging complete / vehicle stop): PowerDelivery-stop -> ... -> reset. */
void din_session_stop(uint32_t now_ms);
const din_session_t *din_session_get(void);
uint8_t din_session_fault(void);

#endif /* DIN_SESSION_H */