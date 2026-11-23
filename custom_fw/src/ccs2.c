/* ccs2.c — CCS2 EVCC top-level controller (REPORT §5.9, Agent B/C/D/E/F/G/H / analyze92-94).
 * Integrates transport->SLAC->SDP->DIN and supplies the charge_stm + current_ctrl EVSE inputs.
 * The autonomous DIN EXI session SM (din_session, Agent F timers/sequence) + the EXI grammar codec
 * (exi/din70121, Agent E) + the live UDP/TCP/IPv6 + mbedTLS transport (v2g_net, Agent G/H) are now
 * BUILT and wired: ccs2_rx routes IPv6 -> v2g_net_rx_ethernet (UDP->SDP / TCP->deframe->ccs2_rx_exi),
 * ccs2_step drives v2g_net_step + din_session_step and starts the TCP transport at SDP-done. INERT:
 * communication only — no power-stage GPIO. The lwIP TCP reliability + mbedTLS crypto are gated
 * third-party hooks; decoded Res also enter via ccs2_rx_exi (bench injection). Confirmed measurement
 * + actuation paths wired. The bench flag-setters remain an alternate injection path.
 */
#include "ccs2.h"
#include "slac.h"
#include "sdp.h"
#include "cp.h"
#include "din70121.h"
#include "din_session.h"
#include "exi.h"
#include "qca7005.h"
#include "v2g_net.h"
#include "ca_store.h"
#include "tick.h"

static uint8_t state;
static ccs2_evse_t evse;

static void z(uint8_t *p, uint16_t n) { for (uint16_t i = 0; i < n; i++) p[i] = 0; }

/* Hook adapters: the transport TX hooks return void; qca7005_frame_send / v2g_net_udp_send return
 * int (status). The inert replica ignores the status (no TX space / not-established -> dropped). */
static void net_eth_send(const uint8_t *frame, uint16_t len) { (void)qca7005_frame_send(frame, len); }
static void net_udp_send(const uint8_t *frame, uint16_t len) { (void)v2g_net_udp_send(frame, len); }

void ccs2_init(void)
{
    z((uint8_t *)&evse, sizeof evse);
    state = CCS2_IDLE;
    slac_init();
    cp_init();
    din70121_init();
    din_session_init();   /* autonomous DIN EXI session SM (Agent F timers/sequence; inert) */
    /* SDP TLS gate = PnC Root-cert count (ca_store, Agent N): count low-byte==0 -> No-TLS (0x10),
     * >0 -> TLS (0x00). ca_store_init reads the ext-SPI cert store (main, after hv/spi4 init). */
    sdp_init(ca_store_root_count());
    /* Live UDP/TCP/IPv6 + mbedTLS transport (v2g_net, Agent G/H / analyze94): wire the Ethernet TX
     * hook to the QCA7005 PLC modem + the SDP UDP send hook. INERT communication carriage — the
     * lwIP TCP reliability + mbedTLS crypto stay gated hooks; no power GPIO. */
    v2g_net_init();
    v2g_net_set_eth_send(net_eth_send);
    sdp_set_send(net_udp_send);
}

/* Sync the EVSE handshake outputs from the autonomous session SM (authoritative while active). */
static void sync_evse_from_session(const din_session_t *ds)
{
    evse.cablecheck_fin  = ds->cablecheck_fin;
    evse.chgparam_ok     = ds->chgparam_ok;
    evse.precharge_flag  = ds->precharge_flag;
    evse.ev_contactor    = ds->ev_contactor;
    evse.precharge_relay = ds->precharge_relay;
    evse.din_isolation   = ds->din_isolation;   /* DIN wire isolation (session CableCheck only) */
    evse.phase_status    = ds->phase_status;    /* EVSE charge-phase marker (engage ==4) */
    /* chademo_isolation_level is hardware-measured (CHAdeMO isolation getter 0x0805206C), NOT
     * sourced from the DIN session — it stays at its bench/hardware-set value (analyze103). */
}

void ccs2_step(uint32_t tick)
{
    evse.plug_in = cp_plug_in();
    evse.link_up = slac_link_up();
    /* Engagement reference for charge_stm state 17 = EVSE PresentVoltage (meas+0x3D18/1A scaled),
     * populated by PreChargeRes/CurrentDemandRes/WeldingRes decoders. NOT the H102 target. Read each
     * tick so both the autonomous-session and bench-injection paths supply the same reference. */
    evse.evse_present_voltage = din_evse_present_voltage_v(din70121_meas());
    v2g_net_step(tick * 10u);   /* transport carriage: TCP connect timeout / idle close / TLS progress */

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
            sdp_init(ca_store_root_count());   /* SDP TLS gate = PnC Root-cert count (ca_store) */
            state = CCS2_SDP;
        }
        break;
    case CCS2_SDP:
        sdp_step(tick);
        if (sdp_get()->state == SDP_ST_TCP_CONNECT || sdp_get()->state == SDP_ST_DONE) {
            evse.secc_found = 1;
            evse.protocol = sdp_get()->selected_protocol;
            /* SECC resolved -> open the TCP transport (state3, timer 30000; TLS iff security==0).
             * The connected event / TLS handshake are gated hooks; the carriage advances via
             * v2g_net_step + bench injection. Communication only — no power drive. */
            v2g_net_start_tcp(sdp_get()->secc_ip, sdp_get()->secc_port,
                              sdp_get()->secc_security, tick * 10u);
            ccs2_session_start();
            din_session_set_evccid(qca7005_mac(), 6u);   /* EVCCID = unit MAC (SessionSetupReq) */
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
 * root 0x4D + DIN header + 6-bit subev + body) -> the autonomous session RX transition engine. The
 * DIN document framing (analyze101/102) is stripped here: exi_decode_header recovers the single
 * root 0x4D, exi_din_decode_doc_start consumes the DIN header (SessionID) + the 6-bit message
 * subev, leaving the body for din_session_rx. The UDP/TCP/IPv6 reassembly that produces these frames
 * is BUILT (v2g_net_rx_ethernet: UDP->SDP / TCP->deframe->here); the live lwIP TCP-connect + mbedTLS
 * handshake hooks stay gated, so on the bench this entry is also driven by explicit injection.
 * Returns the din_session_rx result (EXI_OK / negative error). */
int ccs2_rx_exi(const uint8_t *frame, uint16_t len, uint32_t now_ms)
{
    if (len <= EXI_V2GTP_HDR_LEN) return EXI_ERR_HEADER;
    exi_stream_t s;
    exi_decode_init(&s, frame + EXI_V2GTP_HDR_LEN, len - EXI_V2GTP_HDR_LEN);
    uint8_t root;
    int r = exi_decode_header(&s, &root);          /* leading 0x80 + 7-bit root event */
    if (r) return r;
    if (root != EXI_DIN_ROOT) return EXI_ERR_EVENT;   /* DIN document root 0x4D only */
    uint8_t subev, sid[DIN_SID_MAX]; uint16_t sid_len;
    r = exi_din_decode_doc_start(&s, &subev, sid, &sid_len);   /* DIN header + 6-bit subev */
    if (r) return r;
    /* SessionID negotiation (analyze106): the SessionSetupRes DIN header carries the EVSE-assigned
     * SessionID; adopt it so post-setup Req builders copy it (stock TX wrapper 0x08034C30). Done
     * before din_session_rx so the ServiceDiscoveryReq it emits already uses the negotiated SID. */
    if (subev == DIN_RES_SESSIONSETUP) din_session_set_sid(sid, sid_len);
    /* body = remaining stream bytes after the framing (root + DIN header + subev consumed). */
    const uint8_t *body = frame + EXI_V2GTP_HDR_LEN + s.pos;
    uint16_t body_len = (uint16_t)(len - EXI_V2GTP_HDR_LEN - s.pos);
    return din_session_rx(subev, body, body_len, now_ms);
}

void ccs2_rx(const uint8_t *frame, uint16_t len)
{
    if (len < 14) return;
    uint16_t et = ((uint16_t)frame[12] << 8) | frame[13];
    if (et == 0x88E1u) {           /* HomePlug MME -> SLAC matching */
        slac_rx(frame, len);
    } else if (et == 0x86DDu) {    /* IPv6 -> live transport demux (UDP->SDP / TCP->deframe->EXI) */
        v2g_net_rx_ethernet(frame, len, tick_get() * 10u);
    }
    /* IPv4 (0x0800) / ARP (0x0806): not used by the EVCC session data path. */
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

/* ---- DIN session flag setters (bench injection path; the EXI Res decoders are built + run via
 * ccs2_rx_exi -> din_session_rx in the autonomous session — these mirror their flag effects) ---- */
void ccs2_session_start(void)
{
    if (state == CCS2_SDP || state == CCS2_IDLE) {
        state = CCS2_SESSION;
    }
}

void ccs2_cablecheck_done(uint16_t din_isolation)
{
    evse.cablecheck_fin = 1;
    evse.din_isolation = din_isolation;  /* DIN wire EVSEIsolationStatus (session rule only) */
    evse.phase_status = 3;               /* CableCheckRes writer 0x0802C168 -> meas+0x3D1E=3 */
}

void ccs2_chgparam_done(void) { evse.chgparam_ok = 1; }

void ccs2_precharge_ready(void)
{
    evse.precharge_flag = 1;      /* meas+0x23F */
    evse.phase_status = 4;        /* PreChargeRes writer 0x0802C27A -> meas+0x3D1E=4 (engage prereq) */
}

void ccs2_ev_contactor_closed(void) { evse.ev_contactor = 1; }
void ccs2_precharge_relay_closed(void) { evse.precharge_relay = 1; }
void ccs2_chademo_isolation(uint16_t level) { evse.chademo_isolation_level = level; }

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