/* test_cp_capture.c — host unit test for the CP PWM TIM4 capture signal chain
 * (custom_fw/src/cp_capture.c, REPORT §5.9 Agent J / analyze95). Tests the PURE byte-faithful
 * logic (median 0x08088B9E / publish-deglitch 0x08088A20 / ISR body 0x08088ACE) on a local
 * state struct; the hardware init/ISR wrapper is disasm-verified separately (verify_ccs2.py).
 * Build + run:
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_cp_capture \
 *       test_cp_capture.c src/cp_capture.c && ./test_cp_capture'
 */
#include <stdio.h>
#include <stdint.h>
#include "cp_capture.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

/* feed n valid capture samples (CC1IF|CC2IF = SR 0x6) with given CCR1/CCR2, PD12 low */
static void feed_capture(cp_capture_t *s, int n, uint32_t ccr1, uint32_t ccr2)
{
    for (int i = 0; i < n; i++) cp_capture_process(s, 0x6u, ccr1, ccr2, 0u);
}

int main(void)
{
    /* ---- median: not ready until 16 samples ---- */
    cp_capture_t s = {0};
    uint32_t w = 0;
    for (int i = 0; i < 15; i++) w = cp_capture_median(&s, 500, 1000);
    CHECK(w == 0xFFFFFFFFu, "median returns -1 before 16 samples");
    CHECK(s.median_cnt == 15, "median count 15 after 15 inserts");
    w = cp_capture_median(&s, 500, 1000);
    CHECK(w == ((1000u << 16) | 500u), "median 16th tight sample -> (period<<16)|duty");
    CHECK(s.median_cnt == 0, "median count reset after extraction");

    /* ---- median: insertion sort ascending by duty ---- */
    cp_capture_t s2 = {0};
    uint16_t ds[16] = {500,100,900,200,800,300,700,400,600,150,850,250,750,350,650,450};
    for (int i = 0; i < 16; i++) cp_capture_median(&s2, ds[i], 1000);
    int sorted = 1;
    for (int i = 1; i < 16; i++)
        if ((s2.median_buf[i] & 0xFFFF) < (s2.median_buf[i-1] & 0xFFFF)) sorted = 0;
    /* buf was reset-extracted; re-check sort property via a fresh fill below instead */
    (void)sorted;
    cp_capture_t s3 = {0};
    for (int i = 0; i < 15; i++) cp_capture_median(&s3, ds[i], 1000);
    int sorted3 = 1;
    for (int i = 1; i < 15; i++)
        if ((s3.median_buf[i] & 0xFFFF) < (s3.median_buf[i-1] & 0xFFFF)) sorted3 = 0;
    CHECK(sorted3, "median insertion-sorts ascending by duty");

    /* ---- median: DC extremes rejected (duty 0 / 1000) ---- */
    cp_capture_t s4 = {0};
    for (int i = 0; i < 16; i++) w = cp_capture_median(&s4, 0, 1000);
    CHECK(w == 0xFFFFFFFFu, "median rejects duty-0 cluster (deglitch handles DC)");
    cp_capture_t s5 = {0};
    for (int i = 0; i < 16; i++) w = cp_capture_median(&s5, 1000, 1000);
    CHECK(w == 0xFFFFFFFFu, "median rejects duty-1000 cluster");

    /* ---- median: span > 15 -> no tight window -> -1 ---- */
    cp_capture_t s6 = {0};
    for (int i = 0; i < 16; i++) w = cp_capture_median(&s6, (uint16_t)(100 + 20*i), 1000);
    CHECK(w == 0xFFFFFFFFu, "median span>15 across window -> -1");

    /* ---- median: tight 9-cluster at top of spread found ---- */
    cp_capture_t s7 = {0};
    for (int i = 0; i < 7; i++) cp_capture_median(&s7, 100, 1000);
    for (int i = 0; i < 9; i++) w = cp_capture_median(&s7, 500, 1000);
    CHECK(w == ((1000u << 16) | 500u), "median finds tight 9-cluster (7x100 + 9x500)");

    /* ---- publish/deglitch: state0 intermediate duty leaves state unchanged ---- */
    cp_capture_t p = {0};
    cp_capture_publish(&p, 500, 1000);
    CHECK(p.deglitch_st == 0, "deglitch state0 intermediate duty -> state unchanged");
    /* state0 duty0 -> state1 cnt1 */
    cp_capture_t p2 = {0};
    cp_capture_publish(&p2, 0, 0);
    CHECK(p2.deglitch_st == 1 && p2.deglitch_cnt == 1, "deglitch state0 duty0 -> state1 cnt1");
    /* state0 duty1000 -> state2 cnt1 */
    cp_capture_t p3 = {0};
    cp_capture_publish(&p3, 1000, 0);
    CHECK(p3.deglitch_st == 2 && p3.deglitch_cnt == 1, "deglitch state0 duty1000 -> state2 cnt1");

    /* ---- deglitch zero: 128 consecutive duty0 forces raw duty0 ---- */
    cp_capture_t z = {0};
    for (int i = 0; i < 127; i++) cp_capture_publish(&z, 0, 0);
    CHECK(z.deglitch_st == 1 && z.deglitch_cnt == 127, "deglitch zero cnt127 still confirming");
    cp_capture_publish(&z, 0, 0);   /* 128th */
    CHECK(z.deglitch_st == 0 && z.deglitch_cnt == 0, "deglitch zero 128 -> force + reset");
    CHECK((z.raw_word & 0xFFFFu) == 0, "deglitch zero forces raw duty 0");
    /* a non-zero duty aborts the zero confirmation */
    cp_capture_t z2 = {0};
    cp_capture_publish(&z2, 0, 0);
    cp_capture_publish(&z2, 0, 0);
    cp_capture_publish(&z2, 500, 1000);
    CHECK(z2.deglitch_st == 0, "deglitch zero aborted by non-zero duty -> state0");

    /* ---- deglitch full: 32 consecutive duty1000 forces raw duty1000 ---- */
    cp_capture_t f = {0};
    for (int i = 0; i < 31; i++) cp_capture_publish(&f, 1000, 1000);
    CHECK(f.deglitch_st == 2 && f.deglitch_cnt == 31, "deglitch full cnt31 still confirming");
    cp_capture_publish(&f, 1000, 1000);  /* 32nd */
    CHECK(f.deglitch_st == 0 && f.deglitch_cnt == 0, "deglitch full 32 -> force + reset");
    CHECK(f.raw_word == ((1000u << 16) | 1000u), "deglitch full forces raw (period<<16)|1000");

    /* ---- process: overflow path PD12 high -> duty0, low -> duty1000, hold set ---- */
    cp_capture_t o = {0};
    cp_capture_process(&o, 0x1u, 0, 0, 1u);   /* UIF, PD12 high */
    CHECK(o.hold == 1, "overflow PD12 high sets hold");
    CHECK(o.deglitch_st == 1, "overflow PD12 high -> duty0 -> deglitch state1");
    cp_capture_t o2 = {0};
    cp_capture_process(&o2, 0x1u, 0, 0, 0u);  /* UIF, PD12 low */
    CHECK(o2.deglitch_st == 2, "overflow PD12 low -> duty1000 -> deglitch state2");

    /* ---- process: neither UIF nor both CC flags -> no-op ---- */
    cp_capture_t n = {0};
    cp_capture_process(&n, 0x2u, 1000, 500, 0u);  /* only CC1IF */
    CHECK(n.median_cnt == 0 && n.hold == 0, "process CC1IF-only -> no-op");

    /* ---- process: capture duty formula 1000*CCR2/CCR1, globals after median fills ---- */
    cp_capture_t c = {0};
    feed_capture(&c, 16, 1000, 500);   /* duty = 1000*500/1000 = 500, period 1000 */
    CHECK(c.duty == 500, "capture duty = 1000*CCR2/CCR1 = 500 (per-mille)");
    CHECK(c.period == 1000, "capture period = CCR1 = 1000 us (NOT Hz)");
    CHECK(c.changed == 1, "capture globals changed flag set");
    CHECK(c.upd_count == 1, "capture update counter incremented");
    /* duty 5.0% digital mode: CCR2=50 -> duty 50 */
    cp_capture_t c2 = {0};
    feed_capture(&c2, 16, 1000, 50);
    CHECK(c2.duty == 50, "capture duty 50 = 5.0% (ISO15118 digital)");

    /* ---- process: validity gate CCR1 in [950,1050] ---- */
    cp_capture_t v = {0};
    cp_capture_process(&v, 0x6u, 1100, 500, 0u);  /* CCR1 out of window */
    CHECK(v.hold == 1, "capture CCR1=1100 invalid -> hold set");
    cp_capture_t v2 = {0};
    cp_capture_process(&v2, 0x6u, 1000, 1200, 0u); /* CCR2 > CCR1 */
    CHECK(v2.hold == 1, "capture CCR2>CCR1 invalid -> hold set");
    cp_capture_t v3 = {0};
    cp_capture_process(&v3, 0x6u, 950, 475, 0u);   /* lower boundary valid */
    CHECK(v3.hold == 0, "capture CCR1=950 boundary valid");
    cp_capture_t v4 = {0};
    cp_capture_process(&v4, 0x6u, 1050, 525, 0u);  /* upper boundary valid */
    CHECK(v4.hold == 0, "capture CCR1=1050 boundary valid");

    /* ---- process: hold re-publishes last globals after disturbance ---- */
    cp_capture_t h = {0};
    feed_capture(&h, 16, 1000, 500);    /* establish duty500 period1000 */
    CHECK(h.duty == 500 && h.period == 1000, "hold test: established duty500/period1000");
    cp_capture_process(&h, 0x1u, 0, 0, 1u);  /* disturbance -> hold1 */
    CHECK(h.hold == 1, "hold test: disturbance sets hold");
    cp_capture_process(&h, 0x6u, 1000, 500, 0u); /* next valid -> re-publish last, clear hold */
    CHECK(h.hold == 0, "hold test: next valid capture clears hold (re-publish)");

    /* ---- getters via static cap (drive through process) ---- */
    cp_capture_t *g = (cp_capture_t *)cp_capture_get();
    /* static cap starts zeroed */
    CHECK(cp_capture_duty() == 0 && cp_capture_period() == 0, "getters initial duty/period 0");
    CHECK(cp_capture_update_count() == 0, "getter update_count initial 0");
    feed_capture(g, 16, 1000, 500);
    CHECK(cp_capture_duty() == 500, "getter duty reflects static cap");
    CHECK(cp_capture_period() == 1000, "getter period reflects static cap");
    CHECK(cp_capture_changed() == 1, "getter changed rd-clr returns 1");
    CHECK(cp_capture_changed() == 0, "getter changed cleared after read");
    CHECK(cp_capture_update_count() == 1, "getter update_count reflects static cap");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}