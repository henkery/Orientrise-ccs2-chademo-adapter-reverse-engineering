/* ccs2.h — CCS2 EVCC top-level controller (REPORT §5.9, Agent B/C/D / analyze92).
 *
 * Glue layer that integrates the CCS2 EVSE-side subsystem into the custom adapter app and supplies
 * the EVSE inputs the CHAdeMO charge state machine (charge_stm) + output-current control
 * (current_ctrl) need. Stack (bottom -> top):
 *
 *   qca7005  PLC SPI1 transport (Ethernet frames over HomePlug GreenPHY)        [committed]
 *   slac     ISO15118-3 SLAC matching -> NID/NMK/EVSE-MAC/link-up               [this layer]
 *   cp       CP/PP analog signaling -> plug-in / CP state / digital-5 / D_LINK
 *   sdp      SECC Discovery (V2GTP/UDP) -> SECC IPv6+port+security / protocol
 *   din70121 DIN DC application -> EVSE measurements + CurrentDemand actuation
 *   ccs2     this controller: RX dispatch + session sequencing + EVSE outputs
 *
 * Data flows into the gated CHAdeMO layers:
 *   charge_stm_inputs_t.plug_in        <- cp_plug_in()
 *   charge_stm_inputs_t.phase_status   <- DIN session phase_status (CableCheck=3/PreCharge=4/err=7)
 *   charge_stm_inputs_t.chademo_isolation_level <- CHAdeMO hw isolation measurement (CD interlock)
 *   charge_stm_inputs_t.precharge_flag <- DIN meas+0x23F (CableCheckRes)
 *   charge_stm_inputs_t.cablecheck_fin / chgparam_ok / ev_contactor / precharge_relay <- DIN session
 *   current_ctrl_inputs_t.evse_max_raw/factor   <- din_meas.evse_max_current (+0x3D20/22)
 *   current_ctrl_inputs_t.evse_avail_raw/factor <- din_meas.evse_present_current (+0x3D14/16)
 *   current_ctrl_inputs_t.voltage_limit         <- din_meas.evse_max_voltage (+0x3D08/0A)
 *   CurrentDemandReq actuation: current_ctrl setpoint (ctx+0x16/+0x1c) -> din_set_ev_target
 *                               (meas+0x3CE0/2) -> din_cd_req_encode -> EXI TX (gated transport)
 *
 * RECOVERED + BUILT (Agent E/F, analyze93): the DIN EXI bit-level grammar codec (exi.c primitives +
 * din70121 grammar messages) and the distributed session state machine (din_session.c: state enum
 * 0..13, timers 4000/120000/150000/40000/14000 ms, retry cap 20, CD modulo cadence, FAILED->shutdown
 * + fault post). ccs2_step drives din_session_step and sources the EVSE handshake flags from it while
 * a session is active; decoded Res enter via ccs2_rx_exi. INERT: communication only, no power GPIO.
 *
 * STILL GATED / unresolved: the live UDP/TCP/IPv6 + mbedTLS transport (network reassembly that feeds
 * ccs2_rx_exi), the exact Req-side EXI grammars / root-event numbering [?], the DIN-vs-ISO
 * DC_EVSEStatus layout [?], and the exact EVSEIsolationStatus->level 3/4 mapping. The bench
 * flag-setters remain an alternate injection path when no autonomous session is active. The asserted
 * power-stage drive stays the last gated layer (charge_stm engagement).
 */
#ifndef CCS2_H
#define CCS2_H
#include <stdint.h>
#include "current_ctrl.h"

/* Top-level CCS2 EVCC session state. */
typedef enum {
    CCS2_IDLE = 0,        /* no plug-in / transport down                       */
    CCS2_SLAC,            /* SLAC matching in progress                         */
    CCS2_SDP,             /* SECC discovery in progress                        */
    CCS2_SESSION,         /* DIN EXI session (SessionSetup..CurrentDemand)     */
    CCS2_CURRENT_DEMAND,  /* charging: periodic CurrentDemandReq               */
    CCS2_STOP,            /* session stop / welding detection                  */
    CCS2_FAILED
} ccs2_state_t;

/* EVSE-side handshake outputs consumed by charge_stm (mirrors charge_stm_inputs_t EVSE fields). */
typedef struct {
    uint8_t  link_up;          /* SLAC matched (SET_KEY.CNF ok)               */
    uint8_t  plug_in;          /* CP/PP connector presence                    */
    uint8_t  cablecheck_fin;   /* DIN CableCheck finished OK                  */
    uint8_t  chgparam_ok;      /* DIN ChargeParameterDiscovery OK             */
    uint8_t  ev_contactor;     /* EV contactor closed                         */
    uint8_t  precharge_relay;  /* precharge relay feedback                    */
    uint8_t  precharge_flag;   /* meas+0x23F (engage needs 1)                 */
    /* Three-signal split (analyze103): the engagement guard tests phase_status (==4), the
     * CurrentDemand interlock tests chademo_isolation_level (==3), and din_isolation (0..3)
     * gates only the session CableCheck rule. Feeding DIN isolation into engage==4 never fires. */
    uint16_t phase_status;     /* EVSE charge-phase meas+0x3D1E (engage ==4)  */
    uint16_t chademo_isolation_level; /* CHAdeMO hw isolation level (CD ==3)  */
    uint16_t din_isolation;    /* DIN wire EVSEIsolationStatus 0..3 (session) */
    uint8_t  secc_found;       /* SDP resolved SECC address+port              */
    uint8_t  protocol;         /* selected app protocol (1=DIN, 2=ISO)        */
} ccs2_evse_t;

void ccs2_init(void);
/* Drive the CCS2 subsystem one 100 Hz tick (cp/slac/sdp + session sequencing). */
void ccs2_step(uint32_t tick);
/* QCA7005 RX callback: dispatch by EtherType (MME 0x88E1 -> SLAC; IP -> SDP/DIN when wired). */
void ccs2_rx(const uint8_t *frame, uint16_t len);
/* Gated transport entry: a decoded DIN EXI Res frame (8-byte V2GTP + leading 0x80 + 7-bit event +
 * body) -> the autonomous session RX engine (din_session_rx). The live UDP/TCP/IPv6+TLS reassembly
 * that produces these frames is gated; this is the bench-injection / future-transport hook.
 * `now_ms` is the millisecond timestamp. Returns EXI_OK / negative EXI error. */
int ccs2_rx_exi(const uint8_t *frame, uint16_t len, uint32_t now_ms);
const ccs2_evse_t *ccs2_evse(void);
uint8_t ccs2_state(void);

/* Fill the current_ctrl EVSE-side measurement inputs from the DIN measurement struct. */
void ccs2_fill_current_ctrl(current_ctrl_inputs_t *ci);

/* CurrentDemand actuation: set the EV target current/voltage (from the current_ctrl setpoint,
 * ctx+0x16/+0x1c) into the DIN meas EV-target fields and encode a CurrentDemandReq EXI image.
 * `exi_out` must be >= DIN_CDQ_TX_LEN (108) bytes; returns the encoded length. INERT: the EXI
 * image is produced but the live TCP/TLS send is gated. */
uint16_t ccs2_demand(uint16_t current, uint16_t voltage, uint8_t *exi_out);

/* ---- DIN session flag setters (driven by decoded DIN responses / bench injection) ----
 * The full EXI response decoders for CableCheck/ChargeParameterDiscovery/PreCharge/PowerDelivery
 * are gated (grammar not recovered); these expose the confirmed handshake-flag effects so the
 * session can be driven explicitly. CurrentDemandRes uses the confirmed din_cd_res_decode. */
void ccs2_session_start(void);                 /* SDP done -> begin DIN SessionSetup        */
void ccs2_cablecheck_done(uint16_t din_isolation); /* CableCheckRes finished: din_isolation + phase_status=3 */
void ccs2_chgparam_done(void);                 /* ChargeParameterDiscoveryRes OK            */
void ccs2_precharge_ready(void);               /* PreChargeRes -> precharge_flag=1 + phase_status=4 */
void ccs2_ev_contactor_closed(void);           /* EV contactor closed                       */
void ccs2_precharge_relay_closed(void);        /* precharge relay feedback                  */
void ccs2_chademo_isolation(uint16_t level);   /* CHAdeMO hw isolation level (CD interlock ==3) */
void ccs2_currentdemand_res(const uint8_t *exi); /* CurrentDemandRes EXI field map -> meas  */
void ccs2_session_stop(void);                  /* SessionStop / welding detection           */

#endif /* CCS2_H */