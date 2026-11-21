/* main.c — custom adapter app entry point.
 *
 * SAFETY: this is being built up in incremental, independently-testable layers toward a
 * safe CHAdeMO charge controller (REPORT §5.17–§5.21). The ASSERTED power-stage drive
 * (closing contactors / precharge / charge GPIO) is NOT implemented yet and stays GATED —
 * until it is added and bench-validated, the app never drives an asserted power pin, so all
 * contactors remain open and no HV can appear. gpio_safe_init() only drives DE-ASSERTED
 * (safe) levels; the IWDG key write is a harmless watchdog feed.
 *
 * Current stage: SAFE BOOTSTRAP + CAN1 MESSAGE LAYER + HV MEASUREMENT + INERT CHARGE STM +
 * INERT CURRENT CTRL —
 * restore SYSCLK 168 MHz (rcc), drive every power-stage GPIO to its SAFE/de-asserted state
 * (gpio, §5.5c — contactors open, no HV), init the HV measurement front-end (hv/adc/spi4/nv_cal,
 * §5.21 — ADC1+ADC2 simultaneous PB0/PB1, TIM8-triggered DMA2 accumulation -> live_raw, factory
 * cal read from external SPI4 flash -> get_hv -> outvol), init CAN1 (500k) + the CHAdeMO message
 * layer (can/chademo, §5.8.2/§5.18 — RX H100/H101/H102 parse, periodic H108/H109 standby TX with
 * the measured outvol in H108 byte1-2), run the INERT charge state machine (charge_stm, §5.17 —
 * safe-charge sequence + byte-exact state-17 engagement guard + interlocks + CAN watchdogs, a
 * SHADOW controller that records but does NOT execute power actions), run the INERT H102
 * output-current control law (current_ctrl, §5.21 E — in CurrentDemand, setpoint =
 * min(request, EVSE available) capped by EVSE max, target voltage = min(target, limit); a
 * SHADOW setpoint that drives NO power stage), start the 100 Hz OS tick +
 * 100 kHz timebase (tick, §5.20), and run the periodic 100 Hz loop. A RAM `heartbeat` increments
 * each tick for SWD proof-of-life; hv_* are SWD-readable measurement results, stm_* are
 * SWD-readable state-machine results and cc_* are SWD-readable current-control results.
 * Still NO asserted power-stage drive.
 *
 * Next layers (see README): CCS2 EVSE-side subsystem (PLC/DIN, supplies the stm + current-control
 * EVSE inputs) -> gated power-stage drive (LAST, behind a safety flag). EVSE-side handshake inputs
 * stay safe-stubbed until that subsystem is built.
 */
#include <stdint.h>
#include "rcc.h"
#include "gpio.h"
#include "can.h"
#include "chademo.h"
#include "tick.h"
#include "hv.h"
#include "adc.h"
#include "charge_stm.h"
#include "current_ctrl.h"
#include "qca7005.h"

#define IWDG_KR   (*(volatile uint32_t *)0x40003000u)
#define IWDG_FEED 0x0000AAAAu

volatile uint32_t heartbeat = 0;   /* SWD proof-of-life (RAM only, no side effect) */

/* HV measurement results (SWD-readable; also reported in H108 byte1-2 over CAN). */
volatile int32_t hv_outvol  = 0;   /* get_hv()/10, volts                       */
volatile int32_t hv_raw     = 0;   /* get_hv(), decivolts                      */
volatile int32_t hv_adc_raw = 0;   /* live ADC differential accumulation       */
volatile uint32_t hv_cal_ok = 0;   /* 1 if a valid factory cal was read        */

/* Inert charge state-machine results (SWD-readable; NO power drive — shadow controller). */
volatile uint32_t stm_state    = 0;  /* current CHAdeMO stm state (§5.17)       */
volatile uint32_t stm_interlock = 0; /* active interlock bitmask (STM_IL_*)     */
volatile uint32_t stm_engage   = 0;  /* last state-17 engagement-guard result   */
volatile uint32_t stm_action   = 0;  /* intended (GATED, not executed) action   */

/* Inert H102 current-control results (SWD-readable; NO power drive — shadow setpoint). */
volatile uint32_t cc_setpoint = 0;   /* capped output-current setpoint (A)      */
volatile uint32_t cc_cap      = 0;   /* EVSE max-current cap (A)                */
volatile uint32_t cc_target_v = 0;   /* capped target battery voltage (V)       */

/* CCS2 EVSE-side subsystem — QCA7005 PLC transport (SWD-readable; communication only, no power).
 * The SLAC/SDP/DIN layers above the transport are built next; until then the RX callback just
 * counts received Ethernet frames for bench proof-of-life. */
volatile uint32_t ccs2_qca_ok    = 0;  /* QCA7005 bring-up result (1 = PIB MAC read ok) */
volatile uint32_t ccs2_mac_valid = 0;  /* 1 if the modem PIB MAC was resolved           */
volatile uint32_t ccs2_rx_frames = 0;  /* Ethernet frames received from the PLC modem   */

static void ccs2_rx_count(const uint8_t *frame, uint16_t len)
{
    (void)frame; (void)len;
    ccs2_rx_frames++;   /* placeholder dispatcher; replaced by the CCS2 session layer */
}

static void enable_irq(void)
{
    __asm__ volatile ("cpsie i" ::: "memory");
}

void main(void)
{
    rcc_init();          /* HSE 8 MHz -> PLL 168 MHz; APB1 42 / APB2 84 MHz */
    gpio_safe_init();    /* all power pins -> SAFE/de-asserted (contactors open, no HV) */
    hv_cal_ok = (hv_init() == 0);  /* SPI4 + factory cal + ADC1/2/DMA2/TIM8 front-end (§5.21) */
    can_init();          /* CAN1 500k + acceptance filter + RX0 interrupt (NVIC)     */
    chademo_init();      /* zero the vehicle-data struct + watchdog timestamps       */
    charge_stm_init();   /* inert CHAdeMO charge state machine (shadow, §5.17)       */
    current_ctrl_init(); /* inert H102 output-current control law (shadow, §5.21 E)  */
    tick_init();         /* 100 Hz SysTick OS tick + 100 kHz TIM2 timebase   */
    enable_irq();        /* boot jumped with interrupts masked (cpsid i)     */

    /* CCS2 EVSE-side subsystem — QCA7005 PLC transport bring-up (§5.9). Blocking (IWDG-fed
     * delays), so it runs after tick_init + enable_irq. Communication only — drives no power
     * pin. If no modem is present it times out (~4 s) and reports failure; the app continues.
     * The SLAC/SDP/DIN session layers above it are built next. */
    ccs2_qca_ok = (qca7005_init() == 0);
    qca7005_set_rx_cb(ccs2_rx_count);

    uint32_t next = tick_get();
    for (;;) {
        IWDG_KR = IWDG_FEED;   /* keep watchdog happy; no-op if disabled */
        heartbeat++;           /* 100 Hz proof-of-life counter           */

        /* --- periodic 100 Hz control step --- */
        uint32_t now = tick_get();

        /* HV measurement (§5.21): the ADC front-end accumulates live_raw in its DMA ISR;
         * get_hv interpolates it against the factory cal. Publish for SWD + CAN reporting.
         * MEASUREMENT ONLY — still no asserted power-stage drive. */
        hv_adc_raw = adc_get_live_raw();
        hv_raw     = hv_get_raw();
        hv_outvol  = hv_get_outvol();
        chademo_set_outvol(hv_outvol);   /* H108 byte1-2 = measured volts (450 clamp) */

        chademo_rx_process(now);   /* parse H100/H101/H102 from the CAN RX ring */

        /* Inert charge state machine (§5.17): shadow controller — evaluates the safe-charge
         * sequence + the byte-exact state-17 engagement guard + interlocks + CAN watchdogs, and
         * records the power action each state WOULD drive, but executes NO GPIO. EVSE-side
         * handshake inputs (isolation/precharge_flag/plug_in/…) come from the CCS2 PLC/DIN
         * subsystem that is not built yet -> safe stubs (0), so the machine holds in the early
         * states and the engagement guard cannot pass. outvol is the measured HV (get_hv()/10). */
        charge_stm_inputs_t si;
        si.outvol          = (hv_outvol > 0) ? (uint16_t)hv_outvol : 0u;
        si.isolation       = 0;   /* EVSE-side stub (engage needs 4, CurrentDemand needs 3) */
        si.precharge_flag  = 0;   /* EVSE-side stub [r6+0x23F] (engage needs 1) */
        si.plug_in         = 0;   /* GET_AD_CPD stub */
        si.cablecheck_fin  = 0;   /* EVSE CableCheck-finished stub */
        si.chgparam_ok     = 0;   /* EVSE ChargeParameterDiscovery-OK stub */
        si.ev_contactor    = 0;   /* H102.VehicleStatus EV-contactor stub */
        si.precharge_relay = 0;   /* get_precharge_relay feedback stub */
        si.emergency       = 0;
        si.bms_error       = 0;
        si.hw_fault        = 0;
        si.veh_stop        = 0;
        si.remaining_zero  = 0;
        charge_stm_step(now, &si, chademo_vehicle());
        stm_state     = charge_stm_state();
        stm_interlock = charge_stm_interlock();
        stm_engage    = charge_stm_engage_result();
        stm_action    = charge_stm_action();

        /* Inert H102 current control (§5.21 E): in CurrentDemand (state 30) compute the
         * output-current setpoint = min(H102 request, EVSE available) capped by the EVSE max,
         * and target voltage = min(H102 target, limit). SHADOW — drives NO power stage. The
         * EVSE-side measurements (max/avail current + range-code factors, voltage limit) come
         * from the CCS2 PLC/DIN subsystem not built yet -> safe stubs (0), so avail==0 and the
         * min(request,0)==0 zero-skip holds the setpoint at 0: no current is ever commanded. */
        if (stm_state == STM_CURRENTDEMAND) {
            const chademo_vehicle_t *veh = chademo_vehicle();
            current_ctrl_inputs_t ci;
            ci.current_request   = veh->current_request;   /* H102 byte3 */
            ci.target_voltage    = veh->target_voltage;    /* H102 byte1-2 */
            ci.evse_max_raw      = 0;   /* EVSE max-current raw @0x3D20 — stub */
            ci.evse_max_factor   = 0;   /* EVSE max-current range code @0x3D22 — stub */
            ci.evse_avail_raw    = 0;   /* EVSE present/available raw — stub */
            ci.evse_avail_factor = 0;   /* EVSE present range code — stub */
            ci.voltage_limit     = 0;   /* p[+0x216] output-voltage limit — stub */
            current_ctrl_step(&ci);
        }
        const current_ctrl_t *cc = current_ctrl_get();
        cc_setpoint = cc->setpoint;
        cc_cap      = cc->cap;
        cc_target_v = cc->target_v;

        chademo_tx_periodic(now);  /* H108/H109 standby report every 100 ms     */
        can_service();             /* bus-off recovery / error check            */

        /* CCS2 QCA7005 PLC transport: poll the modem IRQ (PC4) + reg 0xC00, drain RX frames
         * (communication only — no power drive). The session layers above it are built next. */
        qca7005_service();
        ccs2_mac_valid = (qca7005_mac() != 0);

        next++;                              /* advance one 10 ms tick */
        while ((int32_t)(tick_get() - next) < 0) { }
    }
}