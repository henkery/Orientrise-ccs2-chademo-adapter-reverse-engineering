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

    /* --- CurrentDemandReq encode (meas -> EXI, wire factor = stored-3) --- */
    din_set_ev_target(&m, 150, 420, (3u) | (3u << 3));
    m.ev_ready = 1; m.ev_error_code = 0;
    uint8_t out[DIN_CDQ_TX_LEN];
    din_cd_req_encode(&m, out);
    CHECK(out[DIN_CDQ_EXI_TARGET_I] == 150 && out[DIN_CDQ_EXI_TARGET_I + 1] == 0, "targetI EXI[0x18]=150");
    CHECK(out[DIN_CDQ_EXI_TARGET_I_F] == 0, "targetI wire factor 3-3=0");
    CHECK(out[DIN_CDQ_EXI_TARGET_V] == (420 & 0xFF) && out[DIN_CDQ_EXI_TARGET_V + 1] == (420 >> 8),
          "targetV EXI[0x68]=420");
    CHECK(out[DIN_CDQ_EXI_TARGET_V_F] == 0, "targetV wire factor 0");
    CHECK(out[DIN_CDQ_EXI_EVREADY] == 1 && out[DIN_CDQ_EXI_EVSTATUS_TAG] == 1, "DC_EVStatus ready/tag");
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

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}