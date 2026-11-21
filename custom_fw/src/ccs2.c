/* ccs2.c — CCS2 EVCC top-level controller (REPORT §5.9, Agent B/C/D / analyze92).
 * Integrates transport->SLAC->SDP->DIN and supplies the charge_stm + current_ctrl EVSE inputs.
 * INERT: communication only — no power-stage GPIO. The autonomous EXI session + live UDP/TCP/TLS
 * transport are GATED (grammar/timers not recovered); confirmed measurement + actuation paths wired.
 */
#include "ccs2.h"
#include "slac.h"
#include "sdp.h"
#include "cp.h"
#include "din70121.h"
#include "qca7005.h"

static uint8_t state;
static ccs2_evse_t evse;

static void z(uint8_t *p, uint16_t n) { for (uint16_t i = 0; i < n; i++) p[i] = 0; }

void ccs2_init(void)
{
    z((uint8_t *)&evse, sizeof evse);
    state = CCS2_IDLE;
    slac_init();
    cp_init();
    din70121_init();
    sdp_init(0);   /* Root-cert count 0 -> TLS request (config-side; gated until cert config wired) */
}

void ccs2_step(uint32_t tick)
{
    evse.plug_in = cp_plug_in();
    evse.link_up = slac_link_up();

    switch (state) {
    case CCS2_IDLE:
        if (evse.plug_in && qca7005_mac()) {
            slac_init();
            state = CCS2_SLAC;
        }
        break;
    case CCS2_SLAC:
        slac_step(tick);
        if (slac_link_up()) {
            sdp_init(0);
            state = CCS2_SDP;
        }
        break;
    case CCS2_SDP:
        sdp_step(tick);
        if (sdp_get()->state == SDP_ST_TCP_CONNECT || sdp_get()->state == SDP_ST_DONE) {
            evse.secc_found = 1;
            evse.protocol = sdp_get()->selected_protocol;
            ccs2_session_start();
        }
        break;
    case CCS2_SESSION:
        /* DIN session advances via the flag setters (decoded responses). Once CableCheck +
         * ChargeParameterDiscovery + precharge are done, enter CurrentDemand. The autonomous
         * EXI request TX + timers are gated. */
        if (evse.cablecheck_fin && evse.chgparam_ok && evse.precharge_flag) {
            state = CCS2_CURRENT_DEMAND;
        }
        break;
    case CCS2_CURRENT_DEMAND:
        /* periodic CurrentDemandReq driven by main via ccs2_demand (current_ctrl setpoint). */
        break;
    case CCS2_STOP:
    case CCS2_FAILED:
    default:
        break;
    }
}

void ccs2_rx(const uint8_t *frame, uint16_t len)
{
    if (len < 14) return;
    uint16_t et = ((uint16_t)frame[12] << 8) | frame[13];
    if (et == 0x88E1u) {           /* HomePlug MME -> SLAC matching */
        slac_rx(frame, len);
    }
    /* IP (0x86DD IPv6 / 0x0800 IPv4) -> SDP/DIN over the gated UDP/TCP transport (not wired). */
}

const ccs2_evse_t *ccs2_evse(void) { return &evse; }
uint8_t ccs2_state(void) { return state; }

void ccs2_fill_current_ctrl(current_ctrl_inputs_t *ci)
{
    const din_meas_t *m = din70121_meas();
    /* EVSE max-current cap (meas+0x3D20/22) + present/available current (meas+0x3D14/16). */
    ci->evse_max_raw      = m->evse_max_current;
    ci->evse_max_factor   = m->evse_max_current_f;
    ci->evse_avail_raw    = m->evse_present_current;
    ci->evse_avail_factor = m->evse_present_current_f;
    /* output-voltage limit p[+0x216] <- EVSE maximum voltage (meas+0x3D08/0A), scaled to V. */
    ci->voltage_limit     = din_evse_max_voltage_v(m);
}

uint16_t ccs2_demand(uint16_t current, uint16_t voltage, uint8_t *exi_out)
{
    din_meas_t *m = din70121_meas_mut();
    /* setpoint is in real units (A/V) -> multiplier 0 -> stored factor 3 for both targets. */
    din_set_ev_target(m, current, voltage, (uint8_t)(3u | (3u << 3)));
    din_cd_req_encode(m, exi_out);
    return DIN_CDQ_TX_LEN;
}

/* ---- DIN session flag setters (decoded-response effects; EXI decoders gated) ---- */
void ccs2_session_start(void)
{
    if (state == CCS2_SDP || state == CCS2_IDLE) {
        state = CCS2_SESSION;
    }
}

void ccs2_cablecheck_done(uint16_t isolation)
{
    evse.cablecheck_fin = 1;
    evse.isolation = isolation;   /* EVSEIsolationStatus; exact 3/4 mapping gated (Agent D §7) */
}

void ccs2_chgparam_done(void) { evse.chgparam_ok = 1; }

void ccs2_precharge_ready(void)
{
    evse.precharge_flag = 1;      /* evcc_sta+0x23F (CableCheckRes/PreChargeRes) */
}

void ccs2_ev_contactor_closed(void) { evse.ev_contactor = 1; }
void ccs2_precharge_relay_closed(void) { evse.precharge_relay = 1; }

void ccs2_currentdemand_res(const uint8_t *exi)
{
    din_cd_res_decode(exi, din70121_meas_mut());
}

void ccs2_session_stop(void)
{
    state = CCS2_STOP;
    evse.cablecheck_fin = 0;
    evse.chgparam_ok = 0;
    evse.precharge_flag = 0;
}