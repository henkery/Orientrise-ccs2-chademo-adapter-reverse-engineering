/* ccs2.c — CCS2 EVCC top-level controller (REPORT §5.9, Agent B/C/D/E/F / analyze92-93).
 * Integrates transport->SLAC->SDP->DIN and supplies the charge_stm + current_ctrl EVSE inputs.
 * The autonomous DIN EXI session SM (din_session, Agent F timers/sequence) + the EXI grammar codec
 * (exi/din70121, Agent E) are now BUILT and wired: ccs2_step drives din_session_step and, while a
 * session is active, sources the EVSE handshake flags from it. INERT: communication only — no
 * power-stage GPIO. The live UDP/TCP/IPv6+TLS transport stays GATED (not recovered); decoded Res
 * enter via ccs2_rx_exi (bench injection / future transport). Confirmed measurement + actuation
 * paths wired. The bench flag-setters remain an alternate injection path when no session is active.
 */
#include "ccs2.h"
#include "slac.h"
#include "sdp.h"
#include "cp.h"
#include "din70121.h"
#include "din_session.h"
#include "exi.h"
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
    din_session_init();   /* autonomous DIN EXI session SM (Agent F timers/sequence; inert) */
    sdp_init(0);   /* Root-cert count 0 -> TLS request (config-side; gated until cert config wired) */
}

/* Sync the EVSE handshake outputs from the autonomous session SM (authoritative while active). */
static void sync_evse_from_session(const din_session_t *ds)
{
    evse.cablecheck_fin  = ds->cablecheck_fin;
    evse.chgparam_ok     = ds->chgparam_ok;
    evse.precharge_flag  = ds->precharge_flag;
    evse.ev_contactor    = ds->ev_contactor;
    evse.precharge_relay = ds->precharge_relay;
    evse.isolation       = ds->isolation;
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
            din_session_start(tick * 10u);   /* autonomous SM: SessionSetupReq -> await Res (ms) */
        }
        break;
    case CCS2_SESSION:
    case CCS2_CURRENT_DEMAND: {
        /* Drive the autonomous DIN session SM (timer/retry/re-send engine, Agent F). The 100 Hz
         * tick is 10 ms units -> ms = tick*10 (wrap-safe deltas inside din_session). */
        din_session_step(tick * 10u);
        const din_session_t *ds = din_session_get();
        if (ds->session_active) {
            /* Autonomous path: the session SM is authoritative for the EVSE handshake flags. */
            sync_evse_from_session(ds);
            if (ds->fault_flag)                              state = CCS2_FAILED;
            else if (ds->state == DIN_ST_IDLE)               state = CCS2_STOP;
            else if (ds->state >= DIN_ST_POWERDELIVERY_STOP) state = CCS2_STOP;
            else if (ds->state == DIN_ST_CURRENTDEMAND_RES)  state = CCS2_CURRENT_DEMAND;
            else                                             state = CCS2_SESSION;
        } else if (state == CCS2_SESSION) {
            /* Bench path (no autonomous session): the flag setters are authoritative; advance to
             * CurrentDemand once CableCheck + ChargeParameterDiscovery + precharge are done. */
            if (evse.cablecheck_fin && evse.chgparam_ok && evse.precharge_flag)
                state = CCS2_CURRENT_DEMAND;
        }
        break;
    }
    case CCS2_STOP:
    case CCS2_FAILED:
    default:
        break;
    }
}

/* Gated transport entry: a decoded DIN EXI Res frame (8-byte V2GTP header + leading 0x80 + 7-bit
 * root event + body) -> the autonomous session RX transition engine. The live UDP/TCP/IPv6+TLS
 * reassembly that produces these frames is NOT recovered (gated); this is the bench-injection /
 * future-transport hook. Returns the din_session_rx result (EXI_OK / negative error). */
int ccs2_rx_exi(const uint8_t *frame, uint16_t len, uint32_t now_ms)
{
    if (len <= EXI_V2GTP_HDR_LEN) return EXI_ERR_HEADER;
    exi_stream_t s;
    exi_decode_init(&s, frame + EXI_V2GTP_HDR_LEN, len - EXI_V2GTP_HDR_LEN);
    uint8_t ev;
    int r = exi_decode_header(&s, &ev);
    if (r) return r;
    /* body = remaining stream bytes after the leading 0x80 + 7-bit event (2 bytes consumed). */
    const uint8_t *body = frame + EXI_V2GTP_HDR_LEN + s.pos;
    uint16_t body_len = (uint16_t)(len - EXI_V2GTP_HDR_LEN - s.pos);
    return din_session_rx(ev, body, body_len, now_ms);
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