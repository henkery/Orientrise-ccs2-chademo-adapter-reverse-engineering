/* charge_stm.h — INERT CHAdeMO charge state machine (shadow controller), REPORT §5.17/§5.21.
 *
 * Faithful replica of the C013 `CHAdeMO stm` safe-charge SEQUENCE + the safety-critical state-17
 * voltage-engagement guard + the safety interlocks + CAN watchdogs (analyze80/analyze85). It is a
 * SHADOW controller: it tracks the charge state, evaluates the guards/interlocks and records the
 * power action each state WOULD drive, but it drives NO GPIO. The asserted power-stage drive is a
 * later, GATED layer (compile-time safety flag) — until then every power pin stays at its safe
 * de-asserted level (gpio_safe_init), so contactors remain open and no HV can appear.
 *
 * Stock state numbers are kept (p->state halfword @+0x02; transitions `strh rX,[p,#2]`). The
 * state-17 engagement guard is byte-exact (0x0804AF08–0x0804AF30): flag==1 && isolation==4 &&
 * outvol ∈ [ress_vol−10, ress_vol+5] (unsigned) && engage counter >= 250. EVSE-side handshake
 * inputs (isolation / precharge_flag / plug_in / cablecheck_fin / chgparam_ok / ev_contactor /
 * precharge_relay) come from the CCS2 PLC/DIN subsystem that is NOT built yet — main feeds safe
 * stubs (0) so the machine holds in the early/wait states. The guard itself is a pure function and
 * is host-unit-tested (custom_fw/test_charge_stm.c).
 */
#ifndef CHARGE_STM_H
#define CHARGE_STM_H
#include <stdint.h>
#include "chademo.h"

/* Stock CHAdeMO stm state codes (§5.17, analyze80). */
#define STM_IDLE             0u    /* custom idle: no plug-in / session not started */
#define STM_CABLECHECK       13u   /* plug-in/authorize done; EVSE isolation CableCheck */
#define STM_CHGPARAM         14u   /* ChargeParameterDiscovery (CML/CTS); d1 ON */
#define STM_PRECHG_START     15u   /* Switch(d2)=ON, wait EV contactor */
#define STM_EV_CONTACTOR     16u   /* EV contactor closed; wait ChargingCurrentRequest>0 */
#define STM_VOLT_MATCH       17u   /* precharge voltage-match — the engagement guard */
#define STM_PRECHG_RELAY     18u   /* set_precharge_relay (GATED action) */
#define STM_WAIT_TARGET      19u   /* close inner relay, wait TargetBatteryVoltage */
#define STM_CD_PREP          20u   /* CurrentDemand prep (send H108/H109) */
#define STM_CURRENTDEMAND    30u   /* charging; periodic current-limit adjust */
#define STM_STOP_VEH         31u   /* stop by vehicle / isolation warning; wait switchK off */
#define STM_STOP_DONE        32u   /* session stop finished */
#define STM_SWITCHK_OFF      33u   /* wait switchK off */
#define STM_DEENERGIZE       34u   /* output voltage < 10 V -> energizing_state=0 */
#define STM_DEENERGIZED      35u   /* de-energized */
#define STM_STOP_CHARGER     40u   /* abnormal stop by charger (emergency_flag) */
#define STM_NORMAL_END       50u   /* normal charge end */
#define STM_ABNORMAL_VEH     60u   /* abnormal stop by vehicle */
#define STM_TIMEOUT_STOP     300u  /* STM_TIMEOUT_STOP_CHARGER_TRIGGERED */
#define STM_WAIT_ERROR       450u  /* common wait/error pending (CAN-loss safe stop) */
#define STM_BMS_SHUTDOWN     600u  /* notify_bms_shutdown */

/* Timeouts / thresholds in 100 Hz ticks (10 ms) — §5.17/§5.20/§5.21. */
#define STM_ENGAGE_CNT_MIN    250u   /* p[+0x0A] >= 0xFA (2.5 s) engagement dwell */
#define STM_VOLT_MATCH_TOUT   424u   /* p[+0x14] state-17 wait timeout (~4.24 s) */
#define STM_CABLECHECK_TOUT   5000u  /* CableCheck 50 s */
#define STM_CHGPARAM_TOUT     6500u  /* ChargeParameterDiscovery 65 s */
#define STM_D2_TOUT           800u   /* 8 s EV contactor after Switch(d2)=ON */
#define STM_CUR_REQ_TOUT      800u   /* 8 s wait ChargingCurrentRequest>0 after d2=ON */
#define STM_PRECHG_RELAY_TOUT 100u   /* 1 s set_precharge_relay failed -> terminate */
#define STM_SWITCHK_TOUT      400u   /* 4 s wait switchK off */
#define STM_CD_ADJUST         125u   /* CurrentDemand current-limit adjust period (~1.25 s) */
#define STM_DEENERGIZE_MV     10u    /* output voltage < 10 V => de-energized */

/* Interlock reason bitmask (published for SWD/CAN readout). */
#define STM_IL_NONE         0u
#define STM_IL_BUS_LOSS     (1u<<0)  /* whole-bus 1525-tick watchdog -> 450 + disable d1 */
#define STM_IL_MSG_LOSS     (1u<<1)  /* per-message 1 s watchdog (H100/H101/H102) */
#define STM_IL_H102_FAULT   (1u<<2)  /* H102 byte4/5 fault -> h102_status error (300) */
#define STM_IL_EMERGENCY    (1u<<3)  /* emergency_flag==1 -> stop by charger (40) */
#define STM_IL_BMS_ERROR    (1u<<4)  /* bms_error_stop / data_tmout */
#define STM_IL_HW_FAULT     (1u<<5)  /* get_evcc_hw_fault */
#define STM_IL_ISOLATION    (1u<<6)  /* EVSE isolation invalid in CurrentDemand (==3 required) */
#define STM_IL_TIMEOUT      (1u<<7)  /* phase timeout (CableCheck/ChgParam/precharge/volt-match) */

/* Intended power action per state — RECORDED ONLY, never executed (GATED layer). Mirrors §5.5c. */
#define STM_ACT_NONE           0u
#define STM_ACT_D1_ON          1u  /* SET_CSS1(d1) PE7 */
#define STM_ACT_D2_ON          2u  /* SET_CSS2(d2) PE8 */
#define STM_ACT_PRECHG_RELAY   3u  /* PreChargeRELAY PB10/PB11 */
#define STM_ACT_INNER_CONTACTOR 4u /* BatteryPower PD8 */
#define STM_ACT_CHARGE         5u  /* BatteryCharge PC9 */
#define STM_ACT_ALL_OFF        6u  /* de-assert every power pin (safe) */

/* EVSE-side + handshake + interlock inputs. The EVSE-side fields come from the CCS2 PLC/DIN
 * subsystem (not yet built) — main feeds safe stubs (0) until that layer exists. The vehicle
 * request fields (ress_vol/current_request/faults) + CAN freshness are read from chademo_vehicle_t. */
typedef struct {
    uint16_t outvol;          /* EVSE output voltage V = get_hv()/10 (measurement layer) */
    uint16_t isolation;       /* EVSE isolation status (engage==4, CurrentDemand==3) — stub */
    uint8_t  precharge_flag;  /* EVSE precharge-ready flag [r6+0x23F] (engage==1) — stub */
    uint8_t  plug_in;         /* GET_AD_CPD connector plug-in — stub */
    uint8_t  cablecheck_fin;  /* EVSE CableCheck finished OK — stub */
    uint8_t  chgparam_ok;     /* EVSE ChargeParameterDiscovery OK + VehicleChargingEnabled — stub */
    uint8_t  ev_contactor;    /* H102.VehicleStatus: EV contactor closed — stub */
    uint8_t  precharge_relay; /* get_precharge_relay feedback (1=closed) — stub */
    uint8_t  emergency;       /* emergency_flag (stop by charger) */
    uint8_t  bms_error;       /* bms_error_stop / data_tmout */
    uint8_t  hw_fault;        /* get_evcc_hw_fault */
    uint8_t  veh_stop;        /* vehicle requested stop (H102 status) — stub */
    uint8_t  remaining_zero;  /* charging remaining time == 0 */
} charge_stm_inputs_t;

void charge_stm_init(void);
/* Advance one 100 Hz tick. `veh` supplies ress_vol/target_voltage, current_request, fault bytes and
 * the CAN RX timestamps used by the watchdogs. INERT: computes state/guards/interlocks only. */
void charge_stm_step(uint32_t tick, const charge_stm_inputs_t *in, const chademo_vehicle_t *veh);
uint16_t charge_stm_state(void);
uint8_t  charge_stm_interlock(void);   /* active interlock bitmask (STM_IL_*) */
uint8_t  charge_stm_engage_result(void); /* last state-17 guard result (0/1) */
uint8_t  charge_stm_action(void);      /* intended (GATED, not executed) power action STM_ACT_* */

/* Pure, host-testable C013 state-17 engagement guard (0x0804AF08–0x0804AF30, analyze80):
 *   flag==1 && isolation==4 && (outvol+10 >= ress_vol) && (outvol-5 <= ress_vol) && cnt>=250.
 * Unsigned 32-bit arithmetic on zero-extended halfwords (matches add.w/subs + blo/bhi). */
int charge_stm_engage_ok(uint16_t outvol, uint16_t ress_vol, uint16_t cnt,
                         uint16_t isolation, uint8_t flag);

#endif /* CHARGE_STM_H */