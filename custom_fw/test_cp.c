/* test_cp.c — host unit test for CP/PP analog signaling (custom_fw/src/cp.c, REPORT §5.9).
 * Build + run:
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_cp \
 *       test_cp.c src/cp.c && ./test_cp'
 */
#include <stdio.h>
#include <stdint.h>
#include "cp.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

int main(void)
{
    /* --- scaling getters (byte-exact mV) --- */
    CHECK(cp_ad_pp(65520) == 3300,  "AD_PP full-scale 65520 -> 3300 mV");
    CHECK(cp_ad_pp(0) == 0,         "AD_PP 0 -> 0");
    CHECK(cp_ad_pp(32760) == 1650,  "AD_PP half -> 1650 mV");
    CHECK(cp_ad_cpd(32760) == 3300, "AD_CPD full-scale 32760 -> 3300 mV");
    CHECK(cp_ad_bat(32760) == 6600, "AD_BAT full-scale -> 6600 mV (x2 rail)");

    /* --- CP state char (0x08052914) --- */
    CHECK(cp_state_char(0, 0, 0) == CP_STATE_E,   "duty 0 -> 'E'");
    CHECK(cp_state_char(50, 0, 0) == CP_STATE_B,  "duty 50 PD11=0 -> 'B'");
    CHECK(cp_state_char(50, 1, 0) == CP_STATE_C,  "duty 50 PD11=1 -> 'C'");
    CHECK(cp_state_char(50, 0, 1) == CP_STATE_F,  "fault -> 'F'");
    CHECK(cp_state_char(0, 1, 1) == CP_STATE_F,   "fault precedence over duty/PD11");

    /* --- duty-5 detector (0x08052804): [30,70] -> '5' --- */
    CHECK(cp_duty5(30) == CP_DIGITAL_5, "duty 30 -> '5' (lower bound)");
    CHECK(cp_duty5(70) == CP_DIGITAL_5, "duty 70 -> '5' (upper bound)");
    CHECK(cp_duty5(50) == CP_DIGITAL_5, "duty 50 -> '5'");
    CHECK(cp_duty5(29) == 29,           "duty 29 -> raw (below)");
    CHECK(cp_duty5(71) == 71,           "duty 71 -> raw (above)");
    CHECK(cp_duty5(0) == 0,             "duty 0 -> raw 0");

    /* --- PP plug-in debounce (0x080527B0): <=2146 x4 plug, >=2296 x4 unplug --- */
    uint8_t st = 0, cnt = 0;
    /* unplugged, low voltage: needs 4 consecutive samples */
    CHECK(cp_pp_update(2000, &st, &cnt) == 0 && cnt == 1, "plug sample 1");
    CHECK(cp_pp_update(2000, &st, &cnt) == 0 && cnt == 2, "plug sample 2");
    CHECK(cp_pp_update(2000, &st, &cnt) == 0 && cnt == 3, "plug sample 3");
    CHECK(cp_pp_update(2000, &st, &cnt) == 1 && cnt == 0, "plug sample 4 -> plugged");
    /* plugged, high voltage: needs 4 to unplug */
    CHECK(cp_pp_update(2300, &st, &cnt) == 1 && cnt == 1, "unplug sample 1");
    CHECK(cp_pp_update(2300, &st, &cnt) == 1 && cnt == 2, "unplug sample 2");
    CHECK(cp_pp_update(2300, &st, &cnt) == 1 && cnt == 3, "unplug sample 3");
    CHECK(cp_pp_update(2300, &st, &cnt) == 0 && cnt == 0, "unplug sample 4 -> unplugged");
    /* hysteresis: mid-band voltage resets counter, no state change */
    st = 0; cnt = 0;
    cp_pp_update(2000, &st, &cnt);          /* cnt 1 */
    CHECK(cp_pp_update(2200, &st, &cnt) == 0 && cnt == 0, "mid-band (>2146) resets plug counter");
    st = 1; cnt = 0;
    cp_pp_update(2300, &st, &cnt);          /* cnt 1 */
    CHECK(cp_pp_update(2200, &st, &cnt) == 1 && cnt == 0, "mid-band (<2296) resets unplug counter");
    /* boundary: exactly 2146 plugs (<=), exactly 2296 unplugs (>=) */
    st = 0; cnt = 0;
    for (int i = 0; i < 4; i++) cp_pp_update(2146, &st, &cnt);
    CHECK(st == 1, "2146 mV x4 -> plugged (<= boundary)");
    for (int i = 0; i < 4; i++) cp_pp_update(2296, &st, &cnt);
    CHECK(st == 0, "2296 mV x4 -> unplugged (>= boundary)");

    /* --- cp_step integration: digital-5 + plug-in published --- */
    cp_init();
    /* PP raw that scales to ~2000 mV: raw = 2000*65520/3300 = 39709 */
    cp_step(39709, 0, 50, 1000, 0, 1);
    const cp_t *c = cp_get();
    CHECK(c->cp_state == CP_STATE_B, "cp_step duty50 PD11=0 -> 'B'");
    CHECK(c->digital_5 == 1, "cp_step duty50 -> digital_5");
    CHECK(c->d_link == 1, "cp_step D_LINK published");
    CHECK(c->bcb_action == CP_STATE_B, "cp_step BCB recorded 'B' (no GPIO)");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}