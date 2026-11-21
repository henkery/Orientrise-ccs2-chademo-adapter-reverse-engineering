/* charge_stm.c — INERT CHAdeMO charge state machine (shadow controller), REPORT §5.17/§5.21.
 * Faithful C013 safe-charge sequence + byte-exact state-17 engagement guard + interlocks + CAN
 * watchdogs (analyze80/analyze85). SHADOW only: records the power action each state WOULD drive
 * (STM_ACT_*) but executes NO GPIO — the asserted drive is a later GATED layer. Pure logic (no
 * hardware registers), so the engagement guard + sequence are host-unit-testable.
 */
#include "charge_stm.h"

static struct {
    uint16_t state;
    uint16_t engage_cnt;      /* p[+0x0A] engagement dwell counter */
    uint16_t wait_cnt;        /* p[+0x14] state-17 wait counter */
    uint32_t phase_cnt;       /* ticks in current state (p[+4] / phase_cnt) */
    uint32_t enter_tick;
    uint8_t  engage_ok;       /* last state-17 guard result */
    uint8_t  interlock;       /* active interlock bitmask */
    uint8_t  action;          /* intended (GATED, not executed) power action */
    uint8_t  energizing;      /* energizing_state (cleared when outvol < 10 V) */
} stm;

/* ---- byte-exact C013 state-17 engagement guard (0x0804AF08–0x0804AF30, analyze103) ----
 *   ldrb [r6,#0x23f]==1 ; phase-status halfword meas+0x3D1E==4 (PreChargeRes marker, NOT DIN
 *   isolation) ; outvol+10 >= ress_vol (blo fail) ; outvol-5 <= ress_vol (bhi fail) ;
 *   counter p[+0x0A] >= 0xFA(250) (blo fail)  =>  state 17 -> 18.
 * Unsigned 32-bit math on zero-extended halfwords reproduces add.w/subs + unsigned blo/bhi
 * (outvol<5 wraps outvol-5 high -> correctly fails). Window: outvol ∈ [ress_vol−10, ress_vol+5]. */
int charge_stm_engage_ok(uint16_t outvol, uint16_t ress_vol, uint16_t cnt,
                         uint16_t phase_status, uint8_t flag)
{
    if (flag != 1u) return 0;
    if (phase_status != 4u) return 0;
    uint32_t ov = outvol, rv = ress_vol;
    if (ov + 10u < rv) return 0;      /* outvol+10 >= ress_vol */
    if (ov - 5u > rv) return 0;       /* outvol-5  <= ress_vol */
    if (cnt < STM_ENGAGE_CNT_MIN) return 0;
    return 1;
}

void charge_stm_init(void)
{
    stm.state = STM_IDLE;
    stm.engage_cnt = 0; stm.wait_cnt = 0; stm.phase_cnt = 0; stm.enter_tick = 0;
    stm.engage_ok = 0; stm.interlock = STM_IL_NONE; stm.action = STM_ACT_NONE; stm.energizing = 0;
}

uint16_t charge_stm_state(void)         { return stm.state; }
uint8_t  charge_stm_interlock(void)     { return stm.interlock; }
uint8_t  charge_stm_engage_result(void) { return stm.engage_ok; }
uint8_t  charge_stm_action(void)        { return stm.action; }

static void goto_state(uint16_t s, uint32_t tick, uint8_t action)
{
    stm.state = s;
    stm.enter_tick = tick;
    stm.phase_cnt = 0;
    stm.action = action;
    if (s == STM_VOLT_MATCH) { stm.engage_cnt = 0; stm.wait_cnt = 0; stm.engage_ok = 0; }
}

/* Per-message 1 s watchdog: a seen message whose last RX is older than 100 ticks is stale. */
static int msg_stale(uint32_t tick, uint32_t last, uint8_t seen)
{
    return seen && (tick - last) > CHADEMO_MSG_WD_TICKS;
}

/* Compute the interlock bitmask from the CAN watchdogs + H102 faults + EVSE/vehicle fault inputs. */
static uint8_t compute_interlock(uint32_t tick, const charge_stm_inputs_t *in,
                                 const chademo_vehicle_t *veh)
{
    uint8_t il = STM_IL_NONE;
    if (!chademo_bus_fresh(tick)) il |= STM_IL_BUS_LOSS;             /* whole-bus 1525 ticks */
    if (msg_stale(tick, veh->last_h100, veh->h100_seen) ||
        msg_stale(tick, veh->last_h101, veh->h101_seen) ||
        msg_stale(tick, veh->last_h102, veh->h102_seen)) il |= STM_IL_MSG_LOSS;
    if (veh->h102_fault4 || veh->h102_fault5) il |= STM_IL_H102_FAULT;
    if (in->emergency)  il |= STM_IL_EMERGENCY;
    if (in->bms_error)  il |= STM_IL_BMS_ERROR;
    if (in->hw_fault)   il |= STM_IL_HW_FAULT;
    return il;
}

/* Is the state an active charge state where a live interlock must force a safe stop? (450/300/600
 * and the stop/shutdown states are already safe — they hold the recorded stop reason.) */
static int is_active(uint16_t s)
{
    return (s >= STM_CABLECHECK && s <= STM_CURRENTDEMAND);
}

void charge_stm_step(uint32_t tick, const charge_stm_inputs_t *in, const chademo_vehicle_t *veh)
{
    stm.phase_cnt++;
    uint8_t il = compute_interlock(tick, in, veh);

    /* Interlock forcing a safe stop from any active state. Decoded targets: whole-bus loss -> 450
     * (+ disable d1); emergency_flag -> 40 (stop by charger); h102_status error -> 300; bms/hw ->
     * 600/450. No power is driven here — gpio_safe_init already holds every pin de-asserted. */
    if (il != STM_IL_NONE && is_active(stm.state)) {
        stm.interlock = il;
        stm.energizing = 0;
        if (il & STM_IL_EMERGENCY)      goto_state(STM_STOP_CHARGER, tick, STM_ACT_ALL_OFF);
        else if (il & STM_IL_H102_FAULT) goto_state(STM_TIMEOUT_STOP, tick, STM_ACT_ALL_OFF);
        else if (il & (STM_IL_BMS_ERROR | STM_IL_HW_FAULT))
                                         goto_state(STM_BMS_SHUTDOWN, tick, STM_ACT_ALL_OFF);
        else                             goto_state(STM_WAIT_ERROR, tick, STM_ACT_ALL_OFF);
        return;
    }
    /* Active state with no live interlock -> clear it. In stop/wait/terminal states preserve the
     * recorded stop reason (e.g. the one-shot phase timeout) for readout — do not overwrite it. */
    if (is_active(stm.state)) stm.interlock = il;

    uint16_t ress_vol = veh->target_voltage;   /* car-side battery voltage (H102 byte1-2) */

    switch (stm.state) {
    case STM_IDLE:
        stm.action = STM_ACT_NONE;
        if (in->plug_in) { stm.energizing = 1; goto_state(STM_CABLECHECK, tick, STM_ACT_NONE); }
        break;

    case STM_CABLECHECK:   /* 13: EVSE isolation CableCheck (EVSE-side; stubbed handshake) */
        if (in->cablecheck_fin) goto_state(STM_CHGPARAM, tick, STM_ACT_D1_ON);
        else if (stm.phase_cnt > STM_CABLECHECK_TOUT) {
            stm.interlock |= STM_IL_TIMEOUT; goto_state(STM_WAIT_ERROR, tick, STM_ACT_ALL_OFF);
        }
        break;

    case STM_CHGPARAM:     /* 14: ChargeParameterDiscovery; d1 ON; wait VehicleChargingEnabled */
        if (in->chgparam_ok) goto_state(STM_PRECHG_START, tick, STM_ACT_D2_ON);
        else if (stm.phase_cnt > STM_CHGPARAM_TOUT) {
            stm.interlock |= STM_IL_TIMEOUT; goto_state(STM_WAIT_ERROR, tick, STM_ACT_ALL_OFF);
        }
        break;

    case STM_PRECHG_START: /* 15: Switch(d2)=ON; wait EV contactor (H102.VehicleStatus) */
        if (in->ev_contactor) goto_state(STM_EV_CONTACTOR, tick, STM_ACT_D2_ON);
        else if (stm.phase_cnt > STM_D2_TOUT) {
            stm.interlock |= STM_IL_TIMEOUT; goto_state(STM_WAIT_ERROR, tick, STM_ACT_ALL_OFF);
        }
        break;

    case STM_EV_CONTACTOR: /* 16: wait H102.ChargingCurrentRequest > 0 A (decoded) */
        if (veh->current_request > 0u) goto_state(STM_VOLT_MATCH, tick, STM_ACT_D2_ON);
        else if (stm.phase_cnt > STM_CUR_REQ_TOUT) {
            stm.interlock |= STM_IL_TIMEOUT; goto_state(STM_WAIT_ERROR, tick, STM_ACT_ALL_OFF);
        }
        break;

    case STM_VOLT_MATCH: { /* 17: THE engagement guard — C013 stalls until EVSE reaches target */
        stm.engage_cnt++;              /* p[+0x0A] dwell counter */
        stm.wait_cnt++;                /* p[+0x14] wait counter */
        stm.engage_ok = (uint8_t)charge_stm_engage_ok(in->outvol, ress_vol, stm.engage_cnt,
                                                      in->phase_status, in->precharge_flag);
        if (stm.engage_ok) {
            /* match: state 17 -> 18, clear counters (decoded strh r5,[r4,#…] set) */
            stm.engage_cnt = 0; stm.wait_cnt = 0;
            goto_state(STM_PRECHG_RELAY, tick, STM_ACT_PRECHG_RELAY);
        } else if (stm.wait_cnt > STM_VOLT_MATCH_TOUT) {
            stm.interlock |= STM_IL_TIMEOUT; goto_state(STM_WAIT_ERROR, tick, STM_ACT_ALL_OFF);
        }
        break;
    }

    case STM_PRECHG_RELAY: /* 18: set_precharge_relay (GATED); wait feedback; 1 s fail->terminate */
        if (in->precharge_relay) goto_state(STM_WAIT_TARGET, tick, STM_ACT_INNER_CONTACTOR);
        else if (stm.phase_cnt > STM_PRECHG_RELAY_TOUT) {
            stm.interlock |= STM_IL_TIMEOUT; goto_state(STM_WAIT_ERROR, tick, STM_ACT_ALL_OFF);
        }
        break;

    case STM_WAIT_TARGET:  /* 19: close inner relay; wait outvol reaches TargetBatteryVoltage */
        if (in->precharge_relay && in->outvol >= ress_vol)
            goto_state(STM_CD_PREP, tick, STM_ACT_CHARGE);
        else if (stm.phase_cnt > STM_D2_TOUT) {
            stm.interlock |= STM_IL_TIMEOUT; goto_state(STM_WAIT_ERROR, tick, STM_ACT_ALL_OFF);
        }
        break;

    case STM_CD_PREP:      /* 20: CurrentDemand prep (send H108/H109) -> 30 */
        goto_state(STM_CURRENTDEMAND, tick, STM_ACT_CHARGE);
        break;

    case STM_CURRENTDEMAND: /* 30: charging; CHAdeMO hw isolation level==3 required; current adjust */
        if (in->chademo_isolation_level != 3u) {
            stm.interlock |= STM_IL_ISOLATION; goto_state(STM_STOP_VEH, tick, STM_ACT_ALL_OFF);
        } else if (in->veh_stop) {
            goto_state(STM_STOP_VEH, tick, STM_ACT_ALL_OFF);
        } else if (in->remaining_zero) {
            goto_state(STM_NORMAL_END, tick, STM_ACT_ALL_OFF);
        }
        /* every STM_CD_ADJUST ticks the stock recomputes the current limit (setpara(4), §5.21);
         * the output-current control law is the next layer — here we only note the phase. */
        break;

    /* ---- stop / shutdown skeleton (all actions de-asserted; de-energize is the gated layer) ---- */
    case STM_STOP_VEH:     /* 31: wait switchK off (4 s) */
        if (stm.phase_cnt > STM_SWITCHK_TOUT) goto_state(STM_STOP_DONE, tick, STM_ACT_ALL_OFF);
        break;
    case STM_STOP_CHARGER: /* 40: abnormal stop by charger -> shutdown */
        goto_state(STM_STOP_DONE, tick, STM_ACT_ALL_OFF);
        break;
    case STM_ABNORMAL_VEH: /* 60: abnormal stop by vehicle -> shutdown */
        goto_state(STM_STOP_DONE, tick, STM_ACT_ALL_OFF);
        break;
    case STM_STOP_DONE:    /* 32 */
        goto_state(STM_SWITCHK_OFF, tick, STM_ACT_ALL_OFF);
        break;
    case STM_SWITCHK_OFF:  /* 33 */
        goto_state(STM_DEENERGIZE, tick, STM_ACT_ALL_OFF);
        break;
    case STM_DEENERGIZE:   /* 34: output voltage < 10 V -> energizing_state=0 */
        if (in->outvol < STM_DEENERGIZE_MV) {
            stm.energizing = 0; goto_state(STM_DEENERGIZED, tick, STM_ACT_ALL_OFF);
        }
        break;
    case STM_DEENERGIZED:  /* 35 -> normal end */
        goto_state(STM_NORMAL_END, tick, STM_ACT_ALL_OFF);
        break;

    case STM_NORMAL_END:   /* 50: terminal */
    case STM_TIMEOUT_STOP: /* 300: terminal error */
    case STM_BMS_SHUTDOWN: /* 600: terminal */
        stm.action = STM_ACT_ALL_OFF;
        break;

    case STM_WAIT_ERROR:   /* 450: common wait/error pending — hold (safe), record interlock */
        stm.action = STM_ACT_ALL_OFF;
        break;

    default:
        goto_state(STM_WAIT_ERROR, tick, STM_ACT_ALL_OFF);
        break;
    }
}