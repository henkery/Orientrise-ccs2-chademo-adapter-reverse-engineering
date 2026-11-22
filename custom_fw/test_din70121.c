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
/* CurrentDemandRes mandatory prefix (analyze106 ev12): RC(5) + DC_EVSEStatus + PresentVoltage PVT
 * + PresentCurrent PVT + 3 limit-achieved bools. The optional max-limit choice chain follows. */
static void cd_prefix(exi_stream_t *s)
{
    exi_write_bits(s, 5, 0);              /* ResponseCode = OK */
    wr_evse_status(s, 1, 0, 0);           /* DC_EVSEStatus (isolation valid) */
    wr_pvt(s, 0, 3, 400);                 /* EVSEPresentVoltage */
    wr_pvt(s, 0, 1, 100);                 /* EVSEPresentCurrent */
    exi_write_bool(s, 0);                 /* CurrentLimitAchieved */
    exi_write_bool(s, 0);                 /* VoltageLimitAchieved */
    exi_write_bool(s, 0);                 /* PowerLimitAchieved */
}
/* Consume the DC_EVStatus ev17 default grammar (23 bits, analyze101) from a Req body walk;
 * recover EVReady + EVRESSSOC. Mirrors din_dc_ev_status_encode gate/field order. */
static int rd_dc_ev_status(exi_stream_t *s, uint8_t *ready, uint8_t *soc)
{
    uint32_t v; int r;
    r = exi_read_gate(s, EXI_ERR_GATE); if (r) return r;   /* 0xc1 g1 */
    r = exi_read_gate(s, EXI_ERR_GATE); if (r) return r;   /* 0xc1 g2 */
    r = exi_read_bool(s, ready); if (r) return r;          /* EVReady */
    r = exi_read_gate(s, EXI_ERR_GATE); if (r) return r;   /* 0xc1 g3 */
    r = exi_read_bits(s, 2, &v); if (r) return r;          /* 0xc2 choice 2 */
    r = exi_read_gate(s, EXI_ERR_GATE); if (r) return r;
    r = exi_read_bits(s, 4, &v); if (r) return r;          /* 4-bit [body+0x11]=0 */
    r = exi_read_gate(s, EXI_ERR_GATE); if (r) return r;
    r = exi_read_gate(s, EXI_ERR_GATE); if (r) return r;   /* 0xc5 g1 */
    r = exi_read_gate(s, EXI_ERR_GATE); if (r) return r;   /* 0xc5 g2 */
    r = exi_read_bits(s, 7, &v); if (r) return r;          /* EVRESSSOC 7-bit */
    *soc = (uint8_t)v;
    r = exi_read_gate(s, EXI_ERR_GATE); if (r) return r;   /* 0xc5 g3 */
    return exi_read_gate(s, EXI_ERR_GATE);                 /* state 4 terminal gate */
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

    /* --- G8: CurrentDemandRes optional max-limit choice chain (analyze106 ev12 0x23/0x24/0x25) ---
     * Nested optional-element choice, fixed order Current->Voltage->Power, NOT per-field presence.
     * state 0x23 readBits(3): 0=Current,1=Voltage,2=Power,3=end; 0x24 readBits(2): 0=Voltage,
     * 1=Power,2=end; 0x25 readBits(2): 0=Power,1=end. Each present field sets its flag. */
    uint8_t cb[128]; exi_stream_t cs; din_meas_t cm; uint8_t crc; uint16_t cn;

    /* all-absent (choice 3): no flags, previous limits preserved */
    exi_encode_init(&cs, cb, sizeof cb, 0); cd_prefix(&cs);
    exi_write_bits(&cs, 3, 3);                 /* state 0x23: end */
    cn = (uint16_t)exi_encode_finish(&cs);
    memset(&cm, 0, sizeof cm);
    cm.evse_max_current = 111; cm.evse_max_voltage = 222; cm.evse_max_power = 333;
    CHECK(din_cd_res_decode_exi(cb, cn, &cm, &crc) == EXI_OK, "CDRes all-absent decode OK");
    CHECK(cm.evse_max_current_present == 0 && cm.evse_max_voltage_present == 0 &&
          cm.evse_max_power_present == 0, "CDRes all-absent: no present flags");
    CHECK(cm.evse_max_current == 111 && cm.evse_max_voltage == 222 && cm.evse_max_power == 333,
          "CDRes all-absent: keep previous limits");

    /* Current-only (choice 0 -> state 0x24 choice 2 end) */
    exi_encode_init(&cs, cb, sizeof cb, 0); cd_prefix(&cs);
    exi_write_bits(&cs, 3, 0); wr_pvt(&cs, 0, 1, 200);   /* CurrentLimit 200 A */
    exi_write_bits(&cs, 2, 2);                            /* state 0x24: end */
    cn = (uint16_t)exi_encode_finish(&cs);
    memset(&cm, 0, sizeof cm);
    CHECK(din_cd_res_decode_exi(cb, cn, &cm, &crc) == EXI_OK, "CDRes Current-only decode OK");
    CHECK(cm.evse_max_current_present == 1 && cm.evse_max_voltage_present == 0 &&
          cm.evse_max_power_present == 0, "CDRes Current-only: only current flag");
    CHECK(cm.evse_max_current == 200 && cm.evse_max_current_f == 3, "CDRes CurrentLimit 200 f3");

    /* Voltage-only (choice 1 -> state 0x25 choice 1 end) */
    exi_encode_init(&cs, cb, sizeof cb, 0); cd_prefix(&cs);
    exi_write_bits(&cs, 3, 1); wr_pvt(&cs, 0, 3, 500);   /* VoltageLimit 500 V */
    exi_write_bits(&cs, 2, 1);                            /* state 0x25: end */
    cn = (uint16_t)exi_encode_finish(&cs);
    memset(&cm, 0, sizeof cm);
    CHECK(din_cd_res_decode_exi(cb, cn, &cm, &crc) == EXI_OK, "CDRes Voltage-only decode OK");
    CHECK(cm.evse_max_voltage_present == 1 && cm.evse_max_current_present == 0 &&
          cm.evse_max_power_present == 0, "CDRes Voltage-only: only voltage flag");
    CHECK(cm.evse_max_voltage == 500 && cm.evse_max_voltage_f == 3, "CDRes VoltageLimit 500 f3");

    /* Power-only (choice 2 -> terminal) */
    exi_encode_init(&cs, cb, sizeof cb, 0); cd_prefix(&cs);
    exi_write_bits(&cs, 3, 2); wr_pvt(&cs, 0, 3, 300);   /* PowerLimit 300 (mult 0) */
    cn = (uint16_t)exi_encode_finish(&cs);
    memset(&cm, 0, sizeof cm);
    CHECK(din_cd_res_decode_exi(cb, cn, &cm, &crc) == EXI_OK, "CDRes Power-only decode OK");
    CHECK(cm.evse_max_power_present == 1 && cm.evse_max_current_present == 0 &&
          cm.evse_max_voltage_present == 0, "CDRes Power-only: only power flag");
    CHECK(cm.evse_max_power == 300 && cm.evse_max_power_f == 3, "CDRes PowerLimit 300 f3 stored");

    /* all-three (choice 0 -> 0x24 choice 0 -> 0x25 choice 0 -> terminal) */
    exi_encode_init(&cs, cb, sizeof cb, 0); cd_prefix(&cs);
    exi_write_bits(&cs, 3, 0); wr_pvt(&cs, 0, 1, 200);   /* CurrentLimit */
    exi_write_bits(&cs, 2, 0); wr_pvt(&cs, 0, 3, 500);   /* VoltageLimit */
    exi_write_bits(&cs, 2, 0); wr_pvt(&cs, 0, 3, 300);   /* PowerLimit */
    cn = (uint16_t)exi_encode_finish(&cs);
    memset(&cm, 0, sizeof cm);
    CHECK(din_cd_res_decode_exi(cb, cn, &cm, &crc) == EXI_OK, "CDRes all-three decode OK");
    CHECK(cm.evse_max_current_present == 1 && cm.evse_max_voltage_present == 1 &&
          cm.evse_max_power_present == 1, "CDRes all-three: all flags set");
    CHECK(cm.evse_max_current == 200 && cm.evse_max_voltage == 500 && cm.evse_max_power == 300,
          "CDRes all-three: 200/500/300 in Current->Voltage->Power order");

    /* Current+Power, skip Voltage (choice 0 -> 0x24 choice 1 -> terminal) */
    exi_encode_init(&cs, cb, sizeof cb, 0); cd_prefix(&cs);
    exi_write_bits(&cs, 3, 0); wr_pvt(&cs, 0, 1, 200);   /* CurrentLimit */
    exi_write_bits(&cs, 2, 1); wr_pvt(&cs, 0, 3, 300);   /* PowerLimit (Voltage skipped) */
    cn = (uint16_t)exi_encode_finish(&cs);
    memset(&cm, 0, sizeof cm);
    CHECK(din_cd_res_decode_exi(cb, cn, &cm, &crc) == EXI_OK, "CDRes Current+Power decode OK");
    CHECK(cm.evse_max_current_present == 1 && cm.evse_max_power_present == 1 &&
          cm.evse_max_voltage_present == 0, "CDRes Current+Power: voltage absent");

    /* invalid choices -> EXI_ERR_EVENT (0x23 >3 / 0x24 >2 / 0x25 >1) */
    exi_encode_init(&cs, cb, sizeof cb, 0); cd_prefix(&cs);
    exi_write_bits(&cs, 3, 4);                 /* state 0x23: 4 > 3 */
    cn = (uint16_t)exi_encode_finish(&cs);
    memset(&cm, 0, sizeof cm);
    CHECK(din_cd_res_decode_exi(cb, cn, &cm, &crc) == EXI_ERR_EVENT, "CDRes choice 4 (>3) -> ERR_EVENT");
    exi_encode_init(&cs, cb, sizeof cb, 0); cd_prefix(&cs);
    exi_write_bits(&cs, 3, 0); wr_pvt(&cs, 0, 1, 200);
    exi_write_bits(&cs, 2, 3);                 /* state 0x24: 3 > 2 */
    cn = (uint16_t)exi_encode_finish(&cs);
    CHECK(din_cd_res_decode_exi(cb, cn, &cm, &crc) == EXI_ERR_EVENT, "CDRes 0x24 choice 3 (>2) -> ERR_EVENT");
    exi_encode_init(&cs, cb, sizeof cb, 0); cd_prefix(&cs);
    exi_write_bits(&cs, 3, 1); wr_pvt(&cs, 0, 3, 500);
    exi_write_bits(&cs, 2, 2);                 /* state 0x25: 2 > 1 */
    cn = (uint16_t)exi_encode_finish(&cs);
    CHECK(din_cd_res_decode_exi(cb, cn, &cm, &crc) == EXI_ERR_EVENT, "CDRes 0x25 choice 2 (>1) -> ERR_EVENT");

    /* --- analyze106: PreChargeReq body walk — FOUR gates (gate, DC_EVStatus, gate, targetI, gate,
     * targetV, gate EE). The gate between DC_EVStatus and EVTargetCurrent was the missing one. --- */
    din_set_ev_target(mm, 150, 420, (3u) | (3u << 3));
    rn = din_precharge_req_encode(rb, sizeof rb, sid1, 1, mm, 1, 70);
    CHECK(rn > (int)EXI_V2GTP_HDR_LEN, "PreChargeReq encode len>0");
    exi_stream_t bs; uint8_t broot, bch, bsid[DIN_SID_MAX], rdy, soc; uint16_t bsid_len;
    exi_pvt_t bp; uint32_t bv;
    exi_decode_init(&bs, rb + EXI_V2GTP_HDR_LEN, (uint32_t)(rn - EXI_V2GTP_HDR_LEN));
    exi_decode_header(&bs, &broot);
    exi_din_decode_doc_start(&bs, &bch, bsid, &bsid_len);
    CHECK(bch == DIN_REQ_PRECHARGE, "PreChargeReq body choice 0x15");
    CHECK(exi_read_gate(&bs, EXI_ERR_GATE) == EXI_OK, "PreChargeReq gate A (before DC_EVStatus)");
    CHECK(rd_dc_ev_status(&bs, &rdy, &soc) == EXI_OK && rdy == 1 && soc == 70,
          "PreChargeReq DC_EVStatus ready=1 soc=70");
    CHECK(exi_read_gate(&bs, EXI_ERR_GATE) == EXI_OK,
          "PreChargeReq gate B (DC_EVStatus->targetI, analyze106 added)");
    CHECK(exi_read_pvt(&bs, &bp) == EXI_OK && bp.value == 150 && bp.mult == 0 && bp.unit == 1,
          "PreChargeReq EVTargetCurrent 150 A mult0 unit A");
    CHECK(exi_read_gate(&bs, EXI_ERR_GATE) == EXI_OK, "PreChargeReq gate C (targetI->targetV)");
    CHECK(exi_read_pvt(&bs, &bp) == EXI_OK && bp.value == 420 && bp.mult == 0 && bp.unit == 3,
          "PreChargeReq EVTargetVoltage 420 V mult0 unit V");
    CHECK(exi_read_gate(&bs, EXI_ERR_GATE) == EXI_OK, "PreChargeReq gate D (EE)");

    /* --- analyze106: CPDReq prologue body walk — gate gate ETM(3)=DC gate AC/DC-choice(2)=1 gate
     * ev13 DC_EVStatus + maxCurrent PVT + gate + maxPower-absent choice + maxVoltage PVT + gate. --- */
    mm->evse_max_current = 200; mm->evse_max_current_f = 3;
    mm->evse_max_voltage = 500; mm->evse_max_voltage_f = 3;
    rn = din_cpd_req_encode(rb, sizeof rb, sid1, 1, mm, 1, 70);
    CHECK(rn > (int)EXI_V2GTP_HDR_LEN, "CPDReq encode len>0");
    exi_decode_init(&bs, rb + EXI_V2GTP_HDR_LEN, (uint32_t)(rn - EXI_V2GTP_HDR_LEN));
    exi_decode_header(&bs, &broot);
    exi_din_decode_doc_start(&bs, &bch, bsid, &bsid_len);
    CHECK(bch == DIN_REQ_CPD, "CPDReq body choice 0x07");
    CHECK(exi_read_gate(&bs, EXI_ERR_GATE) == EXI_OK, "CPDReq gate A");
    CHECK(exi_read_gate(&bs, EXI_ERR_GATE) == EXI_OK, "CPDReq gate B");
    CHECK(exi_read_bits(&bs, 3, &bv) == EXI_OK && bv == 3, "CPDReq EnergyTransferMode = DC (3)");
    CHECK(exi_read_gate(&bs, EXI_ERR_GATE) == EXI_OK, "CPDReq gate C (before AC/DC choice)");
    CHECK(exi_read_bits(&bs, 2, &bv) == EXI_OK && bv == 1,
          "CPDReq AC/DC choice 1 = DC_EVChargeParameter ev13");
    CHECK(exi_read_gate(&bs, EXI_ERR_GATE) == EXI_OK, "CPDReq ev13 state 0x41 gate");
    CHECK(rd_dc_ev_status(&bs, &rdy, &soc) == EXI_OK && rdy == 1 && soc == 70,
          "CPDReq ev13 DC_EVStatus ready=1 soc=70");
    CHECK(exi_read_pvt(&bs, &bp) == EXI_OK && bp.value == 200 && bp.unit == 1,
          "CPDReq EVMaximumCurrentLimit 200 A");
    CHECK(exi_read_gate(&bs, EXI_ERR_GATE) == EXI_OK, "CPDReq gate (maxCurrent->maxPower choice)");
    CHECK(exi_read_bits(&bs, 2, &bv) == EXI_OK && bv == 1, "CPDReq EVMaximumPowerLimit absent (choice 1)");
    CHECK(exi_read_pvt(&bs, &bp) == EXI_OK && bp.value == 500 && bp.unit == 3,
          "CPDReq EVMaximumVoltageLimit 500 V");
    CHECK(exi_read_gate(&bs, EXI_ERR_GATE) == EXI_OK, "CPDReq trailing gate (EE)");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}