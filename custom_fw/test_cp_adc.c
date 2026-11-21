/* test_cp_adc.c — host unit test for the CP/PP ADC3 acquisition pure logic (cp_adc.c).
 * Verifies the byte-derived accumulation/publish + scaling, INCLUDING the correction that PP
 * accumulates only 2*ch2 (PA2) per event — the 4*ch1 (PA1) sum is a separate byproduct, NOT PP.
 * Build: gcc -O2 -Wall -Wextra -Isrc -o test_cp_adc test_cp_adc.c src/cp_adc.c && ./test_cp_adc
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "cp_adc.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

/* half[8] = SQ1..8 = [ch1, ch2, ch1, ch2, ch1, ch12, ch1, ch0]. */
static void mkhalf(uint16_t *h, uint16_t ch1, uint16_t ch2, uint16_t ch12, uint16_t ch0)
{
    h[0] = ch1; h[1] = ch2; h[2] = ch1; h[3] = ch2;
    h[4] = ch1; h[5] = ch12; h[6] = ch1; h[7] = ch0;
}

int main(void)
{
    cp_adc_t s;
    uint16_t h[8];

    /* --- single event: accumulate, no publish (count < 8) --- */
    memset(&s, 0, sizeof s);
    mkhalf(h, 100, 200, 300, 400);
    cp_adc_publish(&s, h);
    CHECK(s.count == 1, "one event -> count 1");
    CHECK(s.accA == 400, "accA = 2*ch2 = 400 (200+200)");
    CHECK(s.accB == 300, "accB = ch12 = 300");
    CHECK(s.accC == 400, "accC = ch0 = 400");
    CHECK(s.ch1x4 == 400, "ch1x4 byproduct = 4*ch1 = 400 (100x4)");
    CHECK(s.pp_raw == 0 && s.bat_raw == 0 && s.cpd_raw == 0, "no publish before 8 events");

    /* --- PP excludes ch1: identical ch2/ch12/ch0, different ch1 -> same PP, different byproduct --- */
    cp_adc_t a, b;
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    uint16_t ha[8], hb[8];
    mkhalf(ha, 10, 200, 300, 400);    /* ch1 = 10 */
    mkhalf(hb, 4000, 200, 300, 400);  /* ch1 = 4000 (very different) */
    for (int i = 0; i < 8; i++) { cp_adc_publish(&a, ha); cp_adc_publish(&b, hb); }
    CHECK(a.pp_raw == b.pp_raw, "PP raw independent of ch1 (PA1 not folded into PP)");
    CHECK(a.bat_raw == b.bat_raw && a.cpd_raw == b.cpd_raw, "BAT/CPD independent of ch1");
    CHECK(a.ch1x4 == 40 && b.ch1x4 == 16000, "ch1x4 byproduct tracks ch1 (4*10 / 4*4000)");
    CHECK(a.pp_raw == 3200, "PP raw = 16*sum(ch2) = 16*200 = 3200");

    /* --- 8-event constant window: publish + clear --- */
    memset(&s, 0, sizeof s);
    mkhalf(h, 100, 200, 300, 400);
    for (int i = 0; i < 7; i++) cp_adc_publish(&s, h);
    CHECK(s.count == 7 && s.pp_raw == 0, "7 events -> count 7, still no publish");
    CHECK(s.accA == 2800 && s.accB == 2100 && s.accC == 2800, "7-event accumulators (7x400/300/400)");
    cp_adc_publish(&s, h);   /* 8th -> publish */
    CHECK(s.count == 0, "publish resets event counter to 0");
    CHECK(s.pp_raw == 3200, "published PP = 8*(2*200) = 3200 = 16*sum(ch2)");
    CHECK(s.bat_raw == 2400, "published BAT = 8*300 = 2400 = 8*sum(ch12)");
    CHECK(s.cpd_raw == 3200, "published CPD = 8*400 = 3200 = 8*sum(ch0)");
    CHECK(s.accA == 0 && s.accB == 0 && s.accC == 0, "accumulators cleared after publish");
    CHECK(s.ch1x4 == 400, "ch1x4 = last-event 4*ch1 = 400");

    /* --- second window independent of first (accumulators were cleared) --- */
    mkhalf(h, 0, 10, 20, 30);
    for (int i = 0; i < 8; i++) cp_adc_publish(&s, h);
    CHECK(s.pp_raw == 160, "second-window PP = 16*10 = 160 (no carry from first window)");
    CHECK(s.bat_raw == 160 && s.cpd_raw == 240, "second-window BAT=8*20=160 / CPD=8*30=240");

    /* --- full-scale raw words fit uint16_t and match divisor identities --- */
    memset(&s, 0, sizeof s);
    mkhalf(h, 4095, 4095, 4095, 4095);
    for (int i = 0; i < 8; i++) cp_adc_publish(&s, h);
    CHECK(s.pp_raw == 65520, "PP full-scale = 16*4095 = 65520 (fits u16)");
    CHECK(s.bat_raw == 32760, "BAT full-scale = 8*4095 = 32760");
    CHECK(s.cpd_raw == 32760, "CPD full-scale = 8*4095 = 32760");
    CHECK(s.ch1x4 == 16380, "ch1x4 full-scale = 4*4095 = 16380");
    CHECK(65520 == 16 * 4095 && 32760 == 8 * 4095, "divisor identities 65520=16*4095 / 32760=8*4095");

    /* --- scaling getters (byte-exact mV, udiv truncation) --- */
    CHECK(cp_adc_pp_mv(65520) == 3300, "AD_PP full-scale 65520 -> 3300 mV");
    CHECK(cp_adc_pp_mv(0) == 0, "AD_PP zero -> 0 mV");
    CHECK(cp_adc_pp_mv(1) == 0, "AD_PP truncation 1*3300/65520 -> 0");
    CHECK(cp_adc_pp_mv(3200) == 161, "AD_PP 3200*3300/65520 -> 161 (truncated)");
    CHECK(cp_adc_bat_mv(32760) == 6600, "AD_BAT full-scale 32760 -> 6600 mV (x2 rail)");
    CHECK(cp_adc_bat_mv(2400) == 483, "AD_BAT 2400*6600/32760 -> 483 (truncated)");
    CHECK(cp_adc_bat_mv(0) == 0, "AD_BAT zero -> 0");
    CHECK(cp_adc_cpd_mv(32760) == 3300, "AD_CPD full-scale 32760 -> 3300 mV");
    CHECK(cp_adc_cpd_mv(3200) == 322, "AD_CPD 3200*3300/32760 -> 322 (truncated)");
    CHECK(cp_adc_cpd_mv(2) == 0, "AD_CPD 2 mV raw -> 0 (STM >=2 mV gate context)");

    /* --- per-event weighting: ch2 counted twice, ch12/ch0 once, ch1 four times (byproduct) --- */
    memset(&s, 0, sizeof s);
    mkhalf(h, 1, 2, 3, 4);
    cp_adc_publish(&s, h);
    CHECK(s.accA == 4, "ch2 weighted 2x per event (2+2=4)");
    CHECK(s.accB == 3, "ch12 weighted 1x per event");
    CHECK(s.accC == 4, "ch0 weighted 1x per event");
    CHECK(s.ch1x4 == 4, "ch1 weighted 4x per event (1+1+1+1=4) byproduct");

    /* --- varying samples within a window sum correctly (not just constant) --- */
    memset(&s, 0, sizeof s);
    uint32_t expect_pp = 0, expect_bat = 0, expect_cpd = 0;
    for (int i = 0; i < 8; i++) {
        uint16_t ch2 = (uint16_t)(100 + i * 7);
        uint16_t ch12 = (uint16_t)(50 + i * 3);
        uint16_t ch0 = (uint16_t)(20 + i * 5);
        mkhalf(h, 999, ch2, ch12, ch0);   /* ch1 irrelevant to PP/BAT/CPD */
        cp_adc_publish(&s, h);
        expect_pp += 2u * ch2; expect_bat += ch12; expect_cpd += ch0;
    }
    CHECK(s.pp_raw == expect_pp, "varying window PP = sum of 2*ch2 over 8 events");
    CHECK(s.bat_raw == expect_bat, "varying window BAT = sum of ch12 over 8 events");
    CHECK(s.cpd_raw == expect_cpd, "varying window CPD = sum of ch0 over 8 events");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
