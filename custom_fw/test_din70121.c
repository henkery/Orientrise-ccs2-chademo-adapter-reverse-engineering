/* test_din70121.c — host unit test for the DIN70121 measurement + actuation field maps and the
 * corrected power-of-10 PhysicalValueType scaling (custom_fw/src/din70121.c, REPORT §5.9).
 * Build + run (links exi.c — the grammar message codec references the EXI primitives):
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_din70121 \
 *       test_din70121.c src/din70121.c src/exi.c && ./test_din70121'
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "din70121.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

static void st16(uint8_t *p, uint16_t v) { p[0] = v & 0xFF; p[1] = v >> 8; }

/* Synthesize the merged DC_EVSEStatus grammar (analyze103) for round-trip tests:
 * E0(2) [G1 ISO(2) G2] G3 G4 CODE(4) G5 G6 G7 DELAY(u32) G8 G9 G10 NOTIF(2) G11 G12, gates 0. */
static uint16_t mk_evse_status(uint8_t *buf, uint8_t present, uint8_t iso,
                               uint8_t code, uint32_t maxdelay, uint8_t notif)
{
    exi_stream_t s; exi_encode_init(&s, buf, 64, 0);
    exi_write_bits(&s, 2, present ? 0u : 1u);   /* E0 presence */
    if (present) {
        exi_write_bits(&s, 1, 0);               /* G1 */
        exi_write_bits(&s, 2, iso);
        exi_write_bits(&s, 1, 0);               /* G2 */
    }
    exi_write_bits(&s, 1, 0);                   /* G3 */
    exi_write_bits(&s, 1, 0);                   /* G4 */
    exi_write_bits(&s, 4, code);
    exi_write_bits(&s, 1, 0);                   /* G5 */
    exi_write_bits(&s, 1, 0);                   /* G6 */
    exi_write_bits(&s, 1, 0);                   /* G7 */
    exi_write_u32(&s, maxdelay);                /* NotificationMaxDelay (mandatory u32) */
    exi_write_bits(&s, 1, 0);                   /* G8 */
    exi_write_bits(&s, 1, 0);                   /* G9 */
    exi_write_bits(&s, 1, 0);                   /* G10 */
    exi_write_bits(&s, 2, notif);
    exi_write_bits(&s, 1, 0);                   /* G11 */
    exi_write_bits(&s, 1, 0);                   /* G12 */
    return (uint16_t)exi_encode_finish(&s);
}

/* Stream-based DC_EVSEStatus writer (embed mid-body for the B2 Res round-trips). */
static void wr_evse_status(exi_stream_t *s, uint8_t iso, uint8_t code, uint8_t notif)
{
    exi_write_bits(s, 2, 0);                    /* E0 present */
    exi_write_bits(s, 1, 0); exi_write_bits(s, 2, iso); exi_write_bits(s, 1, 0);
    exi_write_bits(s, 1, 0); exi_write_bits(s, 1, 0);
    exi_write_bits(s, 4, code);
    exi_write_bits(s, 1, 0); exi_write_bits(s, 1, 0); exi_write_bits(s, 1, 0);
    exi_write_u32(s, 0);
    exi_write_bits(s, 1, 0); exi_write_bits(s, 1, 0); exi_write_bits(s, 1, 0);
    exi_write_bits(s, 2, notif);
    exi_write_bits(s, 1, 0); exi_write_bits(s, 1, 0);
}
static void wr_pvt(exi_stream_t *s, int8_t mult, uint8_t unit, uint16_t value)
{
    exi_pvt_t p = { .mult = mult, .unit = unit, .unit_present = 1, .value = value };
    exi_write_pvt(s, &p);
}
/* Strip a Req document's framing -> root check + DIN header + 6-bit choice. */
static int req_choice(const uint8_t *buf, uint16_t len, uint8_t *choice, uint8_t *sid, uint16_t *sid_len)
{
    exi_stream_t s; exi_decode_init(&s, buf + EXI_V2GTP_HDR_LEN, len - EXI_V2GTP_HDR_LEN);
    uint8_t root; int r = exi_decode_header(&s, &root); if (r) return r;
    if (root != EXI_DIN_ROOT) return EXI_ERR_EVENT;
    return exi_din_decode_doc_start(&s, choice, sid, sid_len);
}

int main(void)
{
    /* --- pow10 converter table (0x0804E786) --- */
    CHECK(din_pow10(0) == 1,       "pow10(0)==1");
    CHECK(din_pow10(1) == 10,      "pow10(1)==10");
    CHECK(din_pow10(2) == 100,     "pow10(2)==100");
    CHECK(din_pow10(3) == 1000,    "pow10(3)==1000");
    CHECK(din_pow10(4) == 10000,   "pow10(4)==10000");
    CHECK(din_pow10(5) == 100000,  "pow10(5)==100000");
    CHECK(din_pow10(6) == 1000000, "pow10(6)==1000000");
    CHECK(din_pow10(7) == 0xFF,    "pow10(7)==0xFF clamp");
    CHECK(din_pow10(-1) == 0xFF,   "pow10(-1)==0xFF safe");

    /* --- scale: real = raw*10^(factor-3) --- */
    CHECK(din_scale(230, 3) == 230,   "scale(230,3)==230 (mult 0)");
    CHECK(din_scale(2300, 2) == 230,  "scale(2300,2)==230 (mult -1)");
    CHECK(din_scale(23, 4) == 230,    "scale(23,4)==230 (mult +1)");
    CHECK(din_scale(23000, 0) == 23,  "scale(23000,0)==23 (mult -3)");
    CHECK(din_scale(0, 3) == 0,       "scale(0,3)==0");

    /* --- CurrentDemandRes decode (EXI field map -> meas, factor stored = wire+3) --- */
    uint8_t exi[128];
    memset(exi, 0, sizeof exi);
    din_meas_t m;
    memset(&m, 0, sizeof m);
    st16(exi + DIN_CDR_EXI_PRESENT_V, 4000);  exi[DIN_CDR_EXI_PRESENT_V_F] = 0;  /* mult 0 -> f3 */
    st16(exi + DIN_CDR_EXI_PRESENT_I, 125);   exi[DIN_CDR_EXI_PRESENT_I_F] = 0;
    st16(exi + DIN_CDR_EXI_MAX_V, 5000);      exi[DIN_CDR_EXI_MAX_V_F] = 0;  exi[0x24] = 1;
    st16(exi + DIN_CDR_EXI_MAX_I, 200);       exi[DIN_CDR_EXI_MAX_I_F] = 0;  exi[0x2A] = 1;
    exi[DIN_CDR_EXI_CUR_ACHIEVED] = 1;
    exi[DIN_CDR_EXI_VOL_ACHIEVED] = 0;
    exi[DIN_CDR_EXI_PWR_ACHIEVED] = 1;
    din_cd_res_decode(exi, &m);
    CHECK(m.evse_present_voltage == 4000 && m.evse_present_voltage_f == 3, "presentV 4000 f3");
    CHECK(m.evse_present_current == 125 && m.evse_present_current_f == 3, "presentI 125 f3");
    CHECK(m.evse_max_voltage == 5000 && m.evse_max_voltage_f == 3, "maxV 5000 f3 (present)");
    CHECK(m.evse_max_current == 200 && m.evse_max_current_f == 3, "maxI 200 f3 (present)");
    CHECK(m.current_limit_achieved == 1 && m.voltage_limit_achieved == 0 &&
          m.power_limit_achieved == 1, "limit-achieved flags");
    CHECK(din_evse_present_voltage_v(&m) == 4000, "presentV real 4000 V");
    CHECK(din_evse_max_current_a(&m) == 200, "maxI real 200 A");

    /* optional-present clear -> keep previous meas value (fallback) */
    din_meas_t m2 = m;
    memset(exi, 0, sizeof exi);
    st16(exi + DIN_CDR_EXI_MAX_I, 999); exi[DIN_CDR_EXI_MAX_I_F] = 0; exi[0x2A] = 0; /* absent */
    din_cd_res_decode(exi, &m2);
    CHECK(m2.evse_max_current == 200, "maxI absent -> keep previous 200");

    /* factor +3 storage: wire mult -1 (0xFF) -> stored 2 -> scale /10 */
    memset(exi, 0, sizeof exi);
    st16(exi + DIN_CDR_EXI_PRESENT_I, 1250); exi[DIN_CDR_EXI_PRESENT_I_F] = 0xFF; /* mult -1 */
    din_cd_res_decode(exi, &m2);
    CHECK(m2.evse_present_current_f == 2, "wire mult -1 (0xFF) -> stored factor 2");
    CHECK(din_evse_present_current_a(&m2) == 125, "1250 * 10^-1 = 125 A");

    /* --- EV-target setter (arm 0x606): packed factors bits0-2 current, bits3-5 voltage --- */
    din_set_ev_target(&m, 150, 420, (3u) | (3u << 3));   /* both mult 0 -> stored 3 */
    CHECK(m.ev_target_current == 150 && m.ev_target_voltage == 420, "EV targets 150/420");
    CHECK(m.ev_target_current_f == 3 && m.ev_target_voltage_f == 3, "EV target factors 3/3");
    din_set_ev_target(&m, 10, 20, (2u) | (4u << 3));
    CHECK(m.ev_target_current_f == 2 && m.ev_target_voltage_f == 4, "packed factors split 2/4");

    /* --- CurrentDemandReq encode (meas -> EXI, wire factor = stored-3; offsets analyze101) --- */
    din_set_ev_target(&m, 150, 420, (3u) | (3u << 3));
    m.bulk_charging_complete = 1; m.charging_complete = 0;
    uint8_t out[DIN_CDQ_TX_LEN];
    din_cd_req_encode(&m, out);
    CHECK(out[DIN_CDQ_EXI_TARGET_I] == 150 && out[DIN_CDQ_EXI_TARGET_I + 1] == 0, "targetI EXI[0x14]=150");
    CHECK(out[DIN_CDQ_EXI_TARGET_I_F] == 0, "targetI wire factor 3-3=0");
    CHECK(out[DIN_CDQ_EXI_TARGET_V] == (420 & 0xFF) && out[DIN_CDQ_EXI_TARGET_V + 1] == (420 >> 8),
          "targetV EXI[0x64]=420");
    CHECK(out[DIN_CDQ_EXI_TARGET_V_F] == 0, "targetV wire factor 0");
    CHECK(out[DIN_CDQ_EXI_BULK_COMPLETE] == 1 && out[DIN_CDQ_EXI_BULK_GATE] == 1,
          "BulkChargingComplete@0x40 + gate@0x44");
    CHECK(m.first_demand_sent == 1, "first_demand_sent set");

    /* wire factor for stored 2 (mult -1) -> 0xFF */
    din_set_ev_target(&m, 1250, 420, (2u) | (3u << 3));
    din_cd_req_encode(&m, out);
    CHECK(out[DIN_CDQ_EXI_TARGET_I_F] == 0xFF, "stored factor 2 -> wire 0xFF (mult -1)");

    /* init defaults: factors 3 (identity), values 0 -> inert commands nothing */
    din70121_init();
    const din_meas_t *d = din70121_meas();
    CHECK(d->evse_max_current == 0 && d->evse_max_current_f == 3, "init maxI 0 f3");
    CHECK(din_evse_max_current_a(d) == 0, "init inert maxI 0 A");

    /* --- DC_EVSEStatus merged grammar round-trip (analyze103) --- */
    uint8_t sb[64];
    din_dc_evse_status_t st;
    exi_stream_t ss;
    uint16_t sn = mk_evse_status(sb, 1, 1, 5, 12345, 2);
    exi_decode_init(&ss, sb, sn);
    CHECK(din_dc_evse_status_decode(&ss, &st) == EXI_OK, "evsestatus present decode OK");
    CHECK(st.isolation_present == 1 && st.isolation_status == 1, "evsestatus isolation valid");
    CHECK(st.status_code == 5, "evsestatus code 5");
    CHECK(st.notification_max_delay == 12345, "evsestatus mandatory u32 maxdelay 12345");
    CHECK(st.notification == 2, "evsestatus notification 2");
    /* absent isolation (E0==1): no isolation, code/notif/maxdelay intact */
    sn = mk_evse_status(sb, 0, 0, 3, 7, 1);
    exi_decode_init(&ss, sb, sn);
    CHECK(din_dc_evse_status_decode(&ss, &st) == EXI_OK, "evsestatus absent decode OK");
    CHECK(st.isolation_present == 0 && st.status_code == 3 && st.notification == 1 &&
          st.notification_max_delay == 7, "evsestatus absent: code/notif/maxdelay intact");
    /* E0>=2 -> -110 */
    exi_encode_init(&ss, sb, 64, 0); exi_write_bits(&ss, 2, 2); exi_encode_finish(&ss);
    exi_decode_init(&ss, sb, 1);
    CHECK(din_dc_evse_status_decode(&ss, &st) == EXI_ERR_EMPTY, "evsestatus E0>=2 -> -110");
    /* a set gate (G1=1) -> -133 */
    exi_encode_init(&ss, sb, 64, 0);
    exi_write_bits(&ss, 2, 0);   /* E0 present */
    exi_write_bits(&ss, 1, 1);   /* G1 set */
    exi_encode_finish(&ss);
    exi_decode_init(&ss, sb, 1);
    CHECK(din_dc_evse_status_decode(&ss, &st) == EXI_ERR_GATE, "evsestatus G1!=0 -> -133");

    /* --- B2: DC_EVStatus ev17 encoder known vector (EVReady=1, soc=0x46 -> 0x28 0x02 0x30) --- */
    uint8_t evb[8];
    exi_encode_init(&ss, evb, 8, 0);
    CHECK(din_dc_ev_status_encode(&ss, 1, 0x46) == EXI_OK, "DC_EVStatus encode OK");
    uint32_t evn = exi_encode_finish(&ss);
    CHECK(evn == 3 && evb[0] == 0x28 && evb[1] == 0x02 && evb[2] == 0x30,
          "DC_EVStatus wire 0x28 0x02 0x30 (23-bit default grammar)");

    /* --- B2: all 9 Req encoders produce a valid DIN document (root 0x4D + choice + SID) --- */
    din70121_init();
    din_meas_t *mm = din70121_meas_mut();
    din_set_ev_target(mm, 150, 420, (3u) | (3u << 3));
    mm->evse_max_current = 200; mm->evse_max_current_f = 3;
    mm->evse_max_voltage = 500; mm->evse_max_voltage_f = 3;
    uint8_t rb[256]; uint8_t sid[DIN_SID_MAX]; uint16_t sid_len; uint8_t choice;
    uint8_t evccid[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint8_t sid1[1] = { 0x00 };
    int rn;
    struct { const char *name; uint8_t want; } reqs[] = {
        { "SessionSetup", DIN_REQ_SESSIONSETUP }, { "ServiceDiscovery", DIN_REQ_SERVICEDISCOVERY },
        { "CPD", DIN_REQ_CPD }, { "CableCheck", DIN_REQ_CABLECHECK },
        { "PreCharge", DIN_REQ_PRECHARGE }, { "PowerDelivery", DIN_REQ_POWERDELIVERY },
        { "CurrentDemand", DIN_REQ_CURRENTDEMAND }, { "Welding", DIN_REQ_WELDING },
        { "SessionStop", DIN_REQ_SESSIONSTOP },
    };
    for (unsigned i = 0; i < sizeof reqs / sizeof reqs[0]; i++) {
        switch (reqs[i].want) {
        case DIN_REQ_SESSIONSETUP:
            rn = din_sessionsetup_req_encode(rb, sizeof rb, sid1, 1, evccid, 6); break;
        case DIN_REQ_SERVICEDISCOVERY:
            rn = din_servicediscovery_req_encode(rb, sizeof rb, sid1, 1); break;
        case DIN_REQ_CPD:
            rn = din_cpd_req_encode(rb, sizeof rb, sid1, 1, mm, 1, 70); break;
        case DIN_REQ_CABLECHECK:
            rn = din_cablecheck_req_encode(rb, sizeof rb, sid1, 1, 1, 70); break;
        case DIN_REQ_PRECHARGE:
            rn = din_precharge_req_encode(rb, sizeof rb, sid1, 1, mm, 1, 70); break;
        case DIN_REQ_POWERDELIVERY:
            rn = din_powerdelivery_req_encode(rb, sizeof rb, sid1, 1, 0); break;
        case DIN_REQ_CURRENTDEMAND:
            rn = din_cd_req_encode_exi(mm, rb, sizeof rb, sid1, 1); break;
        case DIN_REQ_WELDING:
            rn = din_welding_req_encode(rb, sizeof rb, sid1, 1, 1, 70); break;
        default:
            rn = din_sessionstop_req_encode(rb, sizeof rb, sid1, 1); break;
        }
        char msg[80];
        snprintf(msg, sizeof msg, "%sReq encode len>0", reqs[i].name);
        CHECK(rn > (int)EXI_V2GTP_HDR_LEN, msg);
        int cr = req_choice(rb, (uint16_t)rn, &choice, sid, &sid_len);
        snprintf(msg, sizeof msg, "%sReq framing root 0x4D + choice 0x%02X + SID", reqs[i].name, reqs[i].want);
        CHECK(cr == EXI_OK && choice == reqs[i].want && sid_len == 1 && sid[0] == 0x00, msg);
    }

    /* --- B2: SessionSetupRes decoder (gate gate RC gate EVSEID + opt timestamp) --- */
    exi_encode_init(&ss, sb, 64, 0);
    exi_write_gate(&ss); exi_write_gate(&ss);
    exi_write_bits(&ss, 5, 1);                  /* RC = OK_NewSessionEstablished */
    exi_write_gate(&ss);
    uint8_t id[3] = { 0x41, 0x42, 0x43 };
    exi_write_octet(&ss, id, 3);                /* EVSEID */
    exi_write_bits(&ss, 2, 1);                  /* timestamp absent */
    sn = (uint16_t)exi_encode_finish(&ss);
    uint8_t rc, evseid[32]; uint16_t evseid_len;
    CHECK(din_sessionsetup_res_decode_exi(sb, sn, &rc, evseid, &evseid_len) == EXI_OK,
          "SessionSetupRes decode OK");
    CHECK(rc == 1 && evseid_len == 3 && evseid[0] == 0x41 && evseid[2] == 0x43,
          "SessionSetupRes RC=1 + EVSEID ABC");

    /* --- B2: ServiceDiscoveryRes decoder (RC first) --- */
    exi_encode_init(&ss, sb, 64, 0); exi_write_bits(&ss, 5, 0);
    sn = (uint16_t)exi_encode_finish(&ss);
    CHECK(din_servicediscovery_res_decode_exi(sb, sn, &rc) == EXI_OK && rc == 0,
          "ServiceDiscoveryRes RC=0");

    /* --- B2: CPDRes decoder (RC + processing + choices + DCparam ev15) --- */
    exi_encode_init(&ss, sb, 128, 0);
    exi_write_bits(&ss, 5, 0);                  /* RC */
    exi_write_bits(&ss, 1, 0);                  /* processing finished */
    exi_write_bits(&ss, 2, 1);                  /* sched choice DIN=1 */
    exi_write_bits(&ss, 2, 1);                  /* AC/DC choice DIN=1 -> DCparam */
    wr_evse_status(&ss, 1, 0, 0);               /* DC_EVSEStatus */
    wr_pvt(&ss, 0, 1, 200);                     /* maxCurrent */
    exi_write_bits(&ss, 2, 1);                  /* maxPower absent */
    wr_pvt(&ss, 0, 3, 500);                     /* maxVoltage */
    wr_pvt(&ss, 0, 1, 0);                       /* minCurrent */
    wr_pvt(&ss, 0, 3, 0);                       /* minVoltage */
    exi_write_bits(&ss, 2, 1);                  /* opt absent */
    wr_pvt(&ss, 0, 1, 250);                     /* peak */
    exi_write_bits(&ss, 2, 1);                  /* energy absent */
    sn = (uint16_t)exi_encode_finish(&ss);
    uint8_t proc; din_dc_charge_param_t param;
    CHECK(din_cpd_res_decode_exi(sb, sn, &rc, &proc, &param) == EXI_OK, "CPDRes decode OK");
    CHECK(rc == 0 && proc == 0, "CPDRes RC=0 processing finished");
    CHECK(param.max_current.value == 200 && param.max_voltage.value == 500 &&
          param.peak_current.value == 250 && param.max_power_present == 0 &&
          param.energy_present == 0, "CPDRes DCparam limits (maxI200/maxV500/peak250, opt absent)");
    CHECK(param.status.isolation_status == 1, "CPDRes DCparam DC_EVSEStatus isolation valid");

    /* --- B2: PowerDeliveryRes decoder (gate gate RC gate choice=1 DC_EVSEStatus gate) --- */
    exi_encode_init(&ss, sb, 64, 0);
    exi_write_gate(&ss); exi_write_gate(&ss);
    exi_write_bits(&ss, 5, 0); exi_write_gate(&ss);
    exi_write_bits(&ss, 2, 1);                  /* EVSEStatus choice DIN=1 */
    wr_evse_status(&ss, 1, 2, 0);
    exi_write_gate(&ss);
    sn = (uint16_t)exi_encode_finish(&ss);
    CHECK(din_powerdelivery_res_decode_exi(sb, sn, &rc, &st) == EXI_OK && rc == 0 &&
          st.isolation_status == 1 && st.status_code == 2, "PowerDeliveryRes RC=0 + DC_EVSEStatus");

    /* --- B2: WeldingDetectionRes decoder (gate gate RC gate gate DC_EVSEStatus gate PVT gate) --- */
    exi_encode_init(&ss, sb, 64, 0);
    exi_write_gate(&ss); exi_write_gate(&ss);
    exi_write_bits(&ss, 5, 0); exi_write_gate(&ss); exi_write_gate(&ss);
    wr_evse_status(&ss, 1, 0, 0);
    exi_write_gate(&ss);
    wr_pvt(&ss, 0, 3, 410);                     /* EVSEPresentVoltage */
    exi_write_gate(&ss);
    sn = (uint16_t)exi_encode_finish(&ss);
    din_meas_t wm; memset(&wm, 0, sizeof wm);
    CHECK(din_welding_res_decode_exi(sb, sn, &wm, &rc, &st) == EXI_OK && rc == 0 &&
          wm.evse_present_voltage == 410 && wm.evse_present_voltage_f == 3,
          "WeldingRes RC=0 + presentV 410 f3");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}