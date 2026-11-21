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
 * CCS2 EVSE-side subsystem (§5.9) is now built and wired: QCA7005 PLC SPI1 transport -> SLAC
 * matching (slac) -> CP/PP signaling (cp) -> SDP discovery (sdp/v2gtp) -> DIN70121 measurement +
 * CurrentDemand actuation (din70121), glued by the EVCC controller (ccs2). ccs2_evse() supplies the
 * charge_stm EVSE handshake inputs and ccs2_fill_current_ctrl() supplies the current_ctrl EVSE
 * measurements; ccs2_demand() encodes the CurrentDemandReq EXI image from the setpoint. The
 * autonomous EXI session + live UDP/TCP/IPv6+TLS transport and the CP/PP analog front-end stay
 * GATED (grammar/timers/acquisition not recovered), so the EVSE inputs hold safe 0 and no current
 * is commanded. Communication only — still NO asserted power-stage drive.
 *
 * Next layer (see README): gated power-stage drive (LAST, behind a safety flag), after the CCS2
 * session transport + CP front-end are recovered and outvol is bench-verified.
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
#include "ccs2.h"
#include "cp.h"
#include "cp_capture.h"
#include "cp_adc.h"
#include "din_session.h"
#include "v2g_net.h"
#include "v2g_stack.h"
#include "hw_rng.h"
#include "ca_store.h"

#define IWDG_KR   (*(volatile uint32_t *)0x40003000u)
#define IWDG_FEED 0x0000AAAAu

volatile uint32_t heartbeat = 0;   /* SWD proof-of-life (RAM only, no side effect) */

/* HV measurement results (SWD-readable; also reported in H108 byte1-2 over CAN). */
volatile int32_t hv_outvol  = 0;   /* get_hv()/10, volts                       */
volatile int32_t hv_raw     = 0;   /* get_hv(), decivolts                      */
volatile int32_t hv_adc_raw = 0;   /* live ADC differential accumulation       */
volatile uint32_t hv_cal_ok = 0;   /* 1 if a valid factory cal was read        */

/* CP/PP analog front-end (SWD-readable; MEASUREMENT ONLY — Agent J TIM4 + Agent I ADC3 / analyze95).
 * Two independent acquisition paths drive NO power pin:
 *  - cp_capture: TIM4 input-capture on PD12 (AF2 TIM4_CH1) -> duty per-mille + period us (NOT Hz),
 *    median-of-9 + DC-deglitch in the TIM4 ISR.
 *  - cp_adc: ADC3 (ch2=PA2 PP / ch0=PA0 CPD / ch12=PC2 BAT) off the shared TIM8 125 kHz TRGO,
 *    DMA2 Stream1 circular, ISR sums + publishes every 1.024 ms; plus D_LINK (PB12) / PD11 reads.
 *    PP raw = 16*sum(ch2) (PA2 ONLY — the 4*ch1 PA1 sum is a separate +24V byproduct, NOT PP). */
volatile uint32_t cp_cap_duty   = 0;   /* CP duty per-mille (percent x10; 50 = 5.0%) */
volatile uint32_t cp_cap_period = 0;   /* CP PWM period us (raw CCR1; f_Hz = 1e6/period) */
volatile uint32_t cp_cap_upd    = 0;   /* capture update counter                       */
volatile uint32_t cp_plug       = 0;   /* PP plug-in presence (cp.c hysteresis)        */
volatile uint32_t cp_state      = 0;   /* CP state char 'B'/'C'/'E' (cp.c)             */
volatile uint32_t cp_pp_mv      = 0;   /* AD_PP scaled mV (PA2/ch2, raw*3300/65520)    */
volatile uint32_t cp_cpd_mv     = 0;   /* AD_CPD scaled mV (PA0/ch0, raw*3300/32760)   */
volatile uint32_t cp_bat_mv     = 0;   /* AD_BAT scaled mV (PC2/ch12, raw*6600/32760)  */
volatile uint32_t cp_pp_raw     = 0;   /* published PP raw accumulator (16*sum(ch2))   */
volatile uint32_t cp_cpd_raw    = 0;   /* published CPD raw accumulator (8*sum(ch0))   */
volatile uint32_t cp_d_link     = 0;   /* PB12 PLC modem link status (raw IDR read)    */
volatile uint32_t cp_pd11       = 0;   /* PD11 BCB state read-back (output, drive gated) */

/* Inert charge state-machine results (SWD-readable; NO power drive — shadow controller). */
volatile uint32_t stm_state    = 0;  /* current CHAdeMO stm state (§5.17)       */
volatile uint32_t stm_interlock = 0; /* active interlock bitmask (STM_IL_*)     */
volatile uint32_t stm_engage   = 0;  /* last state-17 engagement-guard result   */
volatile uint32_t stm_action   = 0;  /* intended (GATED, not executed) action   */

/* Inert H102 current-control results (SWD-readable; NO power drive — shadow setpoint). */
volatile uint32_t cc_setpoint = 0;   /* capped output-current setpoint (A)      */
volatile uint32_t cc_cap      = 0;   /* EVSE max-current cap (A)                */
volatile uint32_t cc_target_v = 0;   /* capped target battery voltage (V)       */

/* CCS2 EVSE-side subsystem (SWD-readable; communication only, no power). Full stack now built:
 * QCA7005 PLC transport -> SLAC matching -> SDP discovery -> DIN70121 measurement/actuation,
 * glued by the ccs2 controller (§5.9). The autonomous EXI session + live UDP/TCP/IPv6+TLS
 * transport stay GATED (grammar/timers not recovered); the confirmed measurement + actuation
 * field maps are wired and feed the inert charge_stm + current_ctrl EVSE inputs. */
volatile uint32_t ccs2_qca_ok    = 0;  /* QCA7005 bring-up result (1 = PIB MAC read ok) */
volatile uint32_t ccs2_mac_valid = 0;  /* 1 if the modem PIB MAC was resolved           */
volatile uint32_t ccs2_rx_frames = 0;  /* Ethernet frames received from the PLC modem   */
volatile uint32_t ccs2_st        = 0;  /* CCS2 EVCC session state (CCS2_*)              */
volatile uint32_t ccs2_link      = 0;  /* SLAC matched (NID/NMK established)            */
volatile uint32_t ccs2_secc      = 0;  /* SDP resolved SECC address+port                */
volatile uint32_t ccs2_proto     = 0;  /* selected app protocol (1=DIN, 2=ISO)          */

/* CurrentDemandReq actuation image (SWD-readable; INERT — produced from the current_ctrl setpoint
 * but the live TCP/TLS send is gated). Mirrors charge_stm recording stm_action without executing. */
volatile uint8_t  ccs2_cd_req[108];    /* DIN CurrentDemandReq EXI field image          */
volatile uint32_t ccs2_cd_req_len = 0; /* encoded length (108 when in CurrentDemand)    */

/* Autonomous DIN EXI session SM results (SWD-readable; INERT — din_session, Agent F / analyze93).
 * The session sequence/timers/retries run but drive NO power GPIO; the fault code is recorded
 * (stock fault setter 0x0802C9D0 -> 0x20000774) for the CHAdeMO side to read, not actuated here. */
volatile uint32_t din_st_state  = 0;   /* DIN session state enum 0..13 (which Res awaited) */
volatile uint32_t din_st_fault  = 0;   /* posted fault code (0 none / 1 retry / 2 timeout / 16 iso / 40 resp) */
volatile uint32_t din_st_retry  = 0;   /* resp-wait retry counter (cap 20)                 */
volatile uint32_t din_st_active = 0;   /* 1 while a session is in progress                 */

/* Live UDP/TCP/IPv6 + mbedTLS transport (v2g_net, SWD-readable; INERT communication carriage —
 * Agent G/H / analyze94). The lwIP TCP reliability + mbedTLS crypto are gated hooks; the transport
 * SM (connect/handshake/established/idle-close) + wire framing + EXI dispatch run but drive no power
 * GPIO. mode 1=PLAIN / 2=TLS (CORRECTED: TLS iff SECC security byte==0). */
volatile uint32_t v2g_net_st   = 0;    /* transport state (V2G_NET_*)                       */
volatile uint32_t v2g_net_mode = 0;    /* 0 none / 1 plain / 2 TLS                          */
volatile uint32_t v2g_net_rx   = 0;    /* EXI frames dispatched to ccs2_rx_exi              */
volatile uint32_t v2g_net_tx   = 0;    /* V2GTP frames sent                                 */

/* PnC CA cert store (SWD-readable; INERT communication only — Agent N / analyze96). ca_store reads
 * the ext-SPI PnC cert store; its Root-cert count gates the SDP TLS decision and its DER roots feed
 * the mbedTLS CA chain (v2g_stack_tls_setup). IPv6 ND6 is now lwIP nd6 (driven by v2g_stack_poll).
 * Communication only — no power pin. */
volatile uint32_t ca_root_count = 0;   /* valid PnC Root certs (SDP TLS gate)               */
volatile uint32_t ca_store_present = 0;/* ext-SPI cert store header+checksum valid          */

static void ccs2_rx_dispatch(const uint8_t *frame, uint16_t len)
{
    ccs2_rx_frames++;
    ccs2_rx(frame, len);   /* EtherType dispatch: MME 0x88E1 -> SLAC; IPv6 0x86DD -> live transport */
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
    ca_store_init();     /* PnC CA cert store: read ext-SPI master + populate Root-cert ptr array
                          * (Agent N / §5.9). SPI4 is up (hv_init); the Root count gates SDP TLS.
                          * Communication only — no power drive. */
    cp_capture_init();   /* CP PWM TIM4 input-capture front-end (PD12 AF2, measurement only, §5.9) */
    cp_adc_init();       /* CP/PP ADC3 analog front-end (PA0/1/2+PC2, DMA2 Stream1, shares TIM8, §5.9) */
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
    qca7005_set_rx_cb(ccs2_rx_dispatch);
    hw_rng_init();                          /* STM32 HW-RNG (0x50060800) -> mbedTLS f_rng */
    v2g_stack_set_rng(hw_rng_f_rng, NULL);  /* recovered RNG source (NOT ctr_drbg) */
    ccs2_init();         /* SLAC + CP + SDP + DIN70121 + EVCC controller + transport (comm only) */
    /* Derive the adapter link-local IPv6 + Ethernet src MAC from the QCA7005 PIB MAC
     * (netif_create_ip6_linklocal_address 0x08090D68 / ethernetif_init from_mac=1). */
    if (qca7005_mac()) v2g_net_set_local_mac(qca7005_mac());

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
         * handshake inputs (isolation/precharge_flag/plug_in/…) now come from the CCS2 EVCC
         * controller (ccs2_evse, §5.9); with the autonomous EXI session gated the DIN-derived
         * inputs (isolation/precharge/cablecheck/…) hold 0, so the machine stays in the early
         * states and the engagement guard cannot pass. outvol is the measured HV (get_hv()/10). */
        /* CCS2 EVSE-side subsystem step (§5.9): CP/PP signaling + SLAC + SDP + DIN session
         * sequencing. Communication only — no power drive. BOTH CP/PP acquisition front-ends are
         * now built (Agent J TIM4 + Agent I ADC3 / analyze95): cp_capture supplies the real CP PWM
         * duty (per-mille) + period (us); cp_adc supplies the real PP (PA2/ch2) + CPD (PA0/ch0) raw
         * accumulators, the BAT (PC2/ch12) reading, and the D_LINK (PB12) / PD11 digital reads.
         * plug_in now reflects the measured PP voltage (cp.c hysteresis), but the charge_stm
         * engagement guard still cannot pass: the EVSE-side handshake inputs (isolation/precharge/
         * cablecheck/…) hold safe 0 until the autonomous EXI session is live, and the asserted
         * power-stage drive stays GATED. Measurement only — no asserted power drive. */
        cp_step((uint16_t)cp_adc_pp_raw(), (uint16_t)cp_adc_cpd_raw(),
                cp_capture_duty(), cp_capture_period(), cp_adc_pd11(), cp_adc_d_link());
        cp_cap_duty   = cp_capture_duty();
        cp_cap_period = cp_capture_period();
        cp_cap_upd    = cp_capture_update_count();
        cp_plug       = cp_plug_in();
        cp_state      = cp_get()->cp_state;
        cp_pp_mv      = cp_get()->pp_mv;
        cp_cpd_mv     = cp_get()->cpd_mv;
        cp_bat_mv     = cp_adc_bat_mv(cp_adc_bat_raw());
        cp_pp_raw     = cp_adc_pp_raw();
        cp_cpd_raw    = cp_adc_cpd_raw();
        cp_d_link     = cp_adc_d_link();
        cp_pd11       = cp_adc_pd11();
        ccs2_step(now);
        const ccs2_evse_t *evse = ccs2_evse();

        charge_stm_inputs_t si;
        si.outvol          = (hv_outvol > 0) ? (uint16_t)hv_outvol : 0u;
        /* state-17 engagement reference = EVSE PresentVoltage (meas+0x3D18/1A scaled), NOT the H102
         * TargetBatteryVoltage — C013 0x0804AADA-0x0804AAEE / dual log 0x0804AB40 (ress_vol[364] vs
         * TargetBatteryVoltage[410] on a ZE1). 0 until a PreChargeRes/CurrentDemandRes is decoded. */
        si.evse_present_voltage = evse->evse_present_voltage;
        /* three-signal split (analyze103): the engagement guard tests the EVSE charge-phase
         * marker phase_status==4 (PreChargeRes writer), NOT the DIN isolation wire (0..3); the
         * CurrentDemand interlock tests the CHAdeMO hw isolation level==3 (hardware-sourced via
         * ccs2_chademo_isolation, 0 until wired). din_isolation gates only the session CableCheck
         * rule and is deliberately NOT fed here. */
        si.phase_status    = evse->phase_status;            /* engage guard ==4 (analyze103)  */
        si.chademo_isolation_level = evse->chademo_isolation_level; /* CD interlock ==3       */
        si.precharge_flag  = evse->precharge_flag;  /* meas+0x23F (engage needs 1)            */
        si.plug_in         = evse->plug_in;         /* CP/PP connector presence             */
        si.cablecheck_fin  = evse->cablecheck_fin;  /* DIN CableCheck finished OK           */
        si.chgparam_ok     = evse->chgparam_ok;     /* DIN ChargeParameterDiscovery OK      */
        si.ev_contactor    = evse->ev_contactor;    /* EV contactor closed                  */
        si.precharge_relay = evse->precharge_relay; /* precharge relay feedback             */
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
         * EVSE-side measurements (max/avail current + power-of-10 range factors, voltage limit)
         * now come from the DIN70121 measurement struct via ccs2_fill_current_ctrl (§5.9,
         * meas+0x3D20/22 max, +0x3D14/16 present/avail, +0x3D08/0A max voltage). Until a live
         * CurrentDemandRes is decoded those fields hold 0, so avail==0 and the min(request,0)==0
         * zero-skip holds the setpoint at 0: no current is ever commanded. The asserted current
         * drive is realized upstream as a CCS2 CurrentDemandReq (ccs2_demand), not a local PWM/DAC. */
        if (stm_state == STM_CURRENTDEMAND) {
            const chademo_vehicle_t *veh = chademo_vehicle();
            current_ctrl_inputs_t ci;
            ci.current_request   = veh->current_request;   /* H102 byte3 */
            ci.target_voltage    = veh->target_voltage;    /* H102 byte1-2 */
            ccs2_fill_current_ctrl(&ci);   /* EVSE max/avail current + factors + voltage limit */
            current_ctrl_step(&ci);
        }
        const current_ctrl_t *cc = current_ctrl_get();
        cc_setpoint = cc->setpoint;
        cc_cap      = cc->cap;
        cc_target_v = cc->target_v;

        /* CCS2 CurrentDemand actuation (§5.9 / §5.21 F): encode the setpoint (cc_setpoint A /
         * cc_target_v V) into a DIN CurrentDemandReq EXI image — the asserted current drive is
         * realized upstream as this CCS2 PLC message (EVSE regulates), NOT a local PWM/DAC. INERT:
         * the image is produced for SWD readout but the live TCP/TLS send is gated, so nothing is
         * commanded. Only built while in CurrentDemand; otherwise the length stays 0. */
        if (stm_state == STM_CURRENTDEMAND) {
            ccs2_cd_req_len = ccs2_demand((uint16_t)cc_setpoint, (uint16_t)cc_target_v,
                                          (uint8_t *)ccs2_cd_req);
            /* Send the CurrentDemandReq over the established TCP transport (send router 0x08020338:
             * mode1 plain / mode2 TLS wrap). INERT: returns -1 unless the transport is ESTABLISHED
             * (gated TCP connect/TLS handshake), so nothing is commanded in normal operation. The
             * asserted current drive is realized upstream by the EVSE regulating to this request. */
            (void)v2g_net_tcp_send((const uint8_t *)ccs2_cd_req, (uint16_t)ccs2_cd_req_len, now * 10u);
        } else {
            ccs2_cd_req_len = 0;
        }

        chademo_tx_periodic(now);  /* H108/H109 standby report every 100 ms     */
        can_service();             /* bus-off recovery / error check            */

        /* CCS2 QCA7005 PLC transport: poll the modem IRQ (PC4) + reg 0xC00, drain RX frames
         * into ccs2_rx_dispatch (communication only — no power drive). Publish the EVCC session
         * state for SWD bench readout. */
        qca7005_service();
        ccs2_mac_valid = (qca7005_mac() != 0);
        ccs2_st    = ccs2_state();
        ccs2_link  = evse->link_up;
        ccs2_secc  = evse->secc_found;
        ccs2_proto = evse->protocol;

        /* Autonomous DIN EXI session SM (din_session, §5.9 / analyze93): publish the state /
         * fault / retry for SWD bench readout. INERT — the SM records the fault code each path
         * would post (0x20000774) but drives no power GPIO; the asserted drive stays gated. */
        const din_session_t *ds = din_session_get();
        din_st_state  = ds->state;
        din_st_fault  = ds->fault_code;
        din_st_retry  = ds->retry;
        din_st_active = ds->session_active;

        /* Live transport (v2g_net, §5.9 / analyze94): publish the carriage state / mode / frame
         * counts for SWD bench readout. INERT — communication only, no power drive. */
        const v2g_net_t *vn = v2g_net_get();
        v2g_net_st   = vn->state;
        v2g_net_mode = vn->mode;
        v2g_net_rx   = vn->rx_frames;
        v2g_net_tx   = vn->tx_frames;

        /* PnC CA cert store (Agent N / §5.9): publish the Root-cert count (SDP TLS gate) + store
         * presence. IPv6 ND6 neighbor resolution is now lwIP nd6_input/nd6_tmr (the recovered nd6
         * symbols), driven inside v2g_stack_poll via v2g_net_step. Communication only — no power. */
        ca_root_count = ca_store_root_count();
        ca_store_present = ca_store_get()->store_present;

        next++;                              /* advance one 10 ms tick */
        while ((int32_t)(tick_get() - next) < 0) { }
    }
}