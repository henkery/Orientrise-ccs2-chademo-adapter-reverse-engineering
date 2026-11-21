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
#include "din_session.h"
#include "v2g_net.h"

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
         * controller (ccs2_evse, §5.9); with the CP front-end stubbed unplugged and the autonomous
         * EXI session gated they hold 0, so the machine stays in the early states and the
         * engagement guard cannot pass. outvol is the measured HV (get_hv()/10). */
        /* CCS2 EVSE-side subsystem step (§5.9): CP/PP signaling + SLAC + SDP + DIN session
         * sequencing. Communication only — no power drive. The CP/PP analog front-end (PP/CPD
         * ADC channels + TIM4 CP capture) is not acquired yet, so cp_step is fed a safe
         * "unplugged / no PWM" stub (pp_raw=0xFFFF -> 3300 mV >= unplug threshold, duty 0 ->
         * state 'E'), holding plug_in=0 until that measurement layer is built. The autonomous
         * EXI session + live network transport stay GATED; the session flag setters allow bench
         * injection. ccs2_evse() supplies the confirmed EVSE handshake outputs below. */
        cp_step(0xFFFFu, 0, 0, 0, 0, 0);
        ccs2_step(now);
        const ccs2_evse_t *evse = ccs2_evse();

        charge_stm_inputs_t si;
        si.outvol          = (hv_outvol > 0) ? (uint16_t)hv_outvol : 0u;
        si.isolation       = evse->isolation;       /* DIN EVSE isolation (engage 4 / CD 3) */
        si.precharge_flag  = evse->precharge_flag;  /* DIN evcc_sta+0x23F (engage needs 1)  */
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

        next++;                              /* advance one 10 ms tick */
        while ((int32_t)(tick_get() - next) < 0) { }
    }
}