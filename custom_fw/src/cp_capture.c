/* cp_capture.c — CCS2 Control-Pilot PWM TIM4 input-capture front-end (REPORT §5.9, Agent J /
 * analyze95). Faithful INERT replica of the C013 CP duty/period measurement chain. MEASUREMENT
 * ONLY — captures the CP PWM on PD12 (AF2 TIM4_CH1), drives NO power pin. PD12 is configured by
 * read-modify-write so the gpio_safe PD11/PD8/PD3 de-asserted states are preserved.
 *
 * Byte-derived anchors (C013):
 *   TIM4 init 0x08088A8C, ISR 0x08088ACE, publish/deglitch 0x08088A20, median 0x08088B9E,
 *   duty getter 0x08088B58 ([0x20000A00]), period getter 0x08088B6C ([0x200009FE], us NOT Hz),
 *   PD11 getter 0x08088B88 (GPIOD IDR bit11), vector template 0x080B1B8C vec[46]=0x08088ACF,
 *   VTOR=0x20000000 (stock RAM table; this replica uses the flash vector table + strong ISR),
 *   NVIC ISER0 bit30 (TIM4_IRQn30).
 *
 * The pure signal chain (median/publish/process) is host-tested (test_cp_capture.c); the TIM4/
 * GPIO/NVIC register init + ISR wrapper are disasm-verified (verify_ccs2.py). Power drive GATED.
 */
#include "cp_capture.h"

#define RCC_AHB1ENR   (*(volatile uint32_t *)0x40023830u)
#define RCC_APB1ENR   (*(volatile uint32_t *)0x40023840u)
#define NVIC_ISER0    (*(volatile uint32_t *)0xE000E100u)
#define GPIOD_BASE    0x40020C00u
#define TIM4_BASE     0x40000800u
#define REG(b, o)     (*(volatile uint32_t *)((b) + (o)))
#define REG16(b, o)   (*(volatile uint16_t *)((b) + (o)))

/* TIM4 registers (16-bit writes for CR1/DIER/SR/SMCR/CCMR/CCER/PSC; 32-bit for ARR/CCR3,
 * matching the stock strh/str pattern at 0x08088A8C). */
#define TIM4_CR1      REG16(TIM4_BASE, 0x00u)
#define TIM4_SMCR     REG16(TIM4_BASE, 0x08u)
#define TIM4_DIER     REG16(TIM4_BASE, 0x0Cu)
#define TIM4_SR       REG16(TIM4_BASE, 0x10u)
#define TIM4_CCMR1    REG16(TIM4_BASE, 0x18u)
#define TIM4_CCMR2    REG16(TIM4_BASE, 0x1Cu)
#define TIM4_CCER     REG16(TIM4_BASE, 0x20u)
#define TIM4_PSC      REG16(TIM4_BASE, 0x28u)
#define TIM4_ARR      REG(TIM4_BASE, 0x2Cu)
#define TIM4_CCR1     REG(TIM4_BASE, 0x34u)
#define TIM4_CCR2     REG(TIM4_BASE, 0x38u)
#define TIM4_CCR3     REG(TIM4_BASE, 0x3Cu)
#define GPIOD_MODER   REG(GPIOD_BASE, 0x00u)
#define GPIOD_PUPDR   REG(GPIOD_BASE, 0x0Cu)
#define GPIOD_IDR     REG(GPIOD_BASE, 0x10u)
#define GPIOD_AFRH    REG(GPIOD_BASE, 0x24u)

static cp_capture_t cap;

/* ---- pure signal chain (byte-faithful, host-testable) ---- */

/* median 0x08088B9E: insertion-sort ascending by duty into buf[16] (lo=duty, hi=period); when
 * count reaches 16, scan i=8..15 for the first window with buf[i].duty-buf[i-8].duty <= 15;
 * take the middle buf[i-4]; if its duty is 0 or 1000 reject (return -1, reset count); else
 * return its word. Reset count after extraction. Returns 0xFFFFFFFF (-1) when not ready. */
uint32_t cp_capture_median(cp_capture_t *s, uint16_t duty, uint16_t period)
{
    uint32_t ret = 0xFFFFFFFFu;
    if (s->median_cnt >= CP_CAP_MEDIAN_N) return ret;

    uint32_t idx = 0;
    while (idx < s->median_cnt) {
        uint16_t d = (uint16_t)(s->median_buf[idx] & 0xFFFFu);
        if (d <= duty) { idx++; continue; }
        uint32_t j = s->median_cnt;
        while (j > idx) { s->median_buf[j] = s->median_buf[j - 1]; j--; }
        break;
    }
    s->median_buf[idx] = ((uint32_t)period << 16) | duty;
    s->median_cnt = (uint8_t)(s->median_cnt + 1u);
    if (s->median_cnt < CP_CAP_MEDIAN_N) return ret;

    for (uint32_t i = 8u; i < CP_CAP_MEDIAN_N; i++) {
        uint16_t hi_d = (uint16_t)(s->median_buf[i] & 0xFFFFu);
        uint16_t lo_d = (uint16_t)(s->median_buf[i - 8u] & 0xFFFFu);
        int32_t diff = (int32_t)hi_d - (int32_t)lo_d;
        if (diff > (int32_t)CP_CAP_MEDIAN_SPAN) continue;
        uint32_t mid = i - 4u;
        uint16_t mid_d = (uint16_t)(s->median_buf[mid] & 0xFFFFu);
        if (mid_d != 0u && mid_d != CP_CAP_FULL) ret = s->median_buf[mid];
        break;   /* first tight window decides (match or DC-reject), per stock */
    }
    s->median_cnt = 0u;
    return ret;
}

/* publish 0x08088A20: median insert/extract -> store raw word if > 0; then DC deglitch state
 * machine on the RAW duty/period args. state0: duty0->state1/cnt1, duty1000->state2/cnt1,
 * intermediate->state UNCHANGED. state1: duty!=0->state0; duty0 cnt++ >=128 -> force raw duty0.
 * state2: duty!=1000->state0; duty1000 cnt++ >=32 -> force raw duty1000. Forced raw word uses
 * the ARG period. Returns the raw word. */
uint32_t cp_capture_publish(cp_capture_t *s, uint16_t duty, uint16_t period)
{
    uint32_t word = cp_capture_median(s, duty, period);
    if ((int32_t)word > 0) s->raw_word = word;

    uint8_t st = s->deglitch_st;
    if (st == 0u) {
        if (duty == 0u) { s->deglitch_cnt = 1u; s->deglitch_st = 1u; }
        else if (duty == CP_CAP_FULL) { s->deglitch_cnt = 1u; s->deglitch_st = 2u; }
        /* intermediate duty: state unchanged (stock b 0x08088A88, no state store) */
    } else if (st == 1u) {
        if (duty != 0u) {
            s->deglitch_st = 0u;
        } else {
            uint8_t c = (uint8_t)(s->deglitch_cnt + 1u);
            s->deglitch_cnt = c;
            if (c >= CP_CAP_DEGLITCH_ZERO) {
                s->raw_word = ((uint32_t)period << 16) | 0u;
                s->deglitch_cnt = 0u; s->deglitch_st = 0u;
            }
        }
    } else if (st == 2u) {
        if (duty != CP_CAP_FULL) {
            s->deglitch_st = 0u;
        } else {
            uint8_t c = (uint8_t)(s->deglitch_cnt + 1u);
            s->deglitch_cnt = c;
            if (c >= CP_CAP_DEGLITCH_FULL) {
                s->raw_word = ((uint32_t)period << 16) | CP_CAP_FULL;
                s->deglitch_cnt = 0u; s->deglitch_st = 0u;
            }
        }
    } else {
        s->deglitch_st = 0u;
    }
    return s->raw_word;
}

/* ISR body 0x08088ACE (parameterized hardware readings). sr is the TIM4_SR snapshot (caller
 * clears SR). UIF (bit0) -> overflow/no-edge: PD12 high->duty0 / low->duty1000, period0, hold=1.
 * CC1IF&CC2IF ((sr>>1)&3==3) -> capture: validity (CCR1-950)<=100 && CCR2<=CCR1; hold set ->
 * re-publish last globals + clear hold; else duty=1000*CCR2/CCR1, period=CCR1; invalid ->
 * duty0, period=CCR1, hold=1. Then publish + change-detect store globals. */
void cp_capture_process(cp_capture_t *s, uint32_t sr, uint32_t ccr1, uint32_t ccr2, uint32_t pd12)
{
    uint16_t duty, period;
    if (sr & 1u) {
        duty = (pd12 & 1u) ? 0u : (uint16_t)CP_CAP_FULL;
        period = 0u;
        s->hold = 1u;
    } else if (((sr >> 1) & 3u) == 3u) {
        if ((uint32_t)(ccr1 - CP_CAP_VALID_LO) <= CP_CAP_VALID_SPAN && ccr2 <= ccr1) {
            if (s->hold) {
                duty = s->duty; period = s->period; s->hold = 0u;
            } else {
                duty = (uint16_t)((1000u * ccr2) / ccr1);
                period = (uint16_t)ccr1;
            }
        } else {
            duty = 0u; period = (uint16_t)ccr1; s->hold = 1u;
        }
    } else {
        return;
    }

    uint32_t word = cp_capture_publish(s, duty, period);
    uint16_t new_duty = (uint16_t)(word & 0xFFFFu);
    uint16_t new_period = (uint16_t)(word >> 16);
    if (new_duty != s->duty || new_period != s->period) {
        s->duty = new_duty;
        s->period = new_period;
        s->changed = 1u;
        s->upd_count++;
    }
}

/* ---- hardware init + ISR wrapper (disasm-verified) ---- */

void cp_capture_init(void)
{
    cap.changed = 0; cap.hold = 0; cap.deglitch_st = 0; cap.median_cnt = 0;
    cap.deglitch_cnt = 0; cap.period = 0; cap.duty = 0; cap.upd_count = 0; cap.raw_word = 0;
    for (uint32_t i = 0; i < CP_CAP_MEDIAN_N; i++) cap.median_buf[i] = 0;

    RCC_AHB1ENR |= (1u << 3);    /* GPIOD */
    RCC_APB1ENR |= (1u << 2);    /* TIM4 */
    (void)RCC_AHB1ENR; (void)RCC_APB1ENR;

    /* PD12 -> AF2 (TIM4_CH1), pull-up. Read-modify-write ONLY PD12 bits so the gpio_safe
     * PD11/PD8/PD3 de-asserted states are preserved (measurement only, no power pin change). */
    GPIOD_MODER = (GPIOD_MODER & ~(3u << 24)) | (2u << 24);   /* MODER12 = 10 AF      */
    GPIOD_AFRH  = (GPIOD_AFRH  & ~(0xFu << 16)) | (2u << 16); /* AFRH12  = 2  AF2     */
    GPIOD_PUPDR = (GPIOD_PUPDR & ~(3u << 24)) | (1u << 24);   /* PUPDR12 = 01 pull-up */

    /* TIM4 register init — byte-exact order (0x08088A8C), no EGR/UG forced. */
    TIM4_DIER  = 0u;
    TIM4_SR    = 0u;
    TIM4_CR1   = 0u;
    TIM4_PSC   = (uint16_t)CP_TIM4_PSC;     /* 83 -> 1 us/tick */
    TIM4_ARR   = CP_TIM4_ARR;               /* 1110 */
    TIM4_SMCR  = (uint16_t)CP_TIM4_SMCR;    /* 0x54 reset mode TS=TI1FP1 */
    TIM4_CCMR1 = (uint16_t)CP_TIM4_CCMR1;   /* 0x201 */
    TIM4_CCMR2 = 0u;
    TIM4_CCR3  = CP_TIM4_CCR3;              /* 1100 heartbeat */
    TIM4_CCER  = (uint16_t)CP_TIM4_CCER;    /* 0x13 */
    TIM4_SR    = 0u;
    TIM4_DIER  = (uint16_t)CP_TIM4_DIER;    /* 0x0A CC1IE|CC3IE */
    TIM4_CR1   = (uint16_t)CP_TIM4_CR1;     /* 0x81 CEN|ARPE */

    NVIC_ISER0 = (1u << 30);                /* TIM4_IRQn = 30 */
}

void TIM4_IRQHandler(void)
{
    uint32_t sr = TIM4_SR;
    TIM4_SR = 0u;                            /* clear ALL flags (stock strh 0) */
    uint32_t ccr1 = TIM4_CCR1;
    uint32_t ccr2 = TIM4_CCR2;
    uint32_t pd12 = (GPIOD_IDR >> 12) & 1u;
    cp_capture_process(&cap, sr, ccr1, ccr2, pd12);
}

const cp_capture_t *cp_capture_get(void) { return &cap; }
uint16_t cp_capture_duty(void) { return cap.duty; }
uint16_t cp_capture_period(void) { return cap.period; }
uint32_t cp_capture_update_count(void) { return cap.upd_count; }
uint8_t cp_capture_changed(void)
{
    uint8_t c = cap.changed;
    cap.changed = 0u;
    return c;
}