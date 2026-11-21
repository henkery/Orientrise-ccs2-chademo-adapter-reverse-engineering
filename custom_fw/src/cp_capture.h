/* cp_capture.h — CCS2 Control-Pilot PWM TIM4 input-capture front-end (REPORT §5.9, Agent J /
 * analyze95). Faithful INERT replica of the C013 CP duty/period measurement chain:
 *   TIM4 init 0x08088A8C : PD12 AF2 TIM4_CH1, PSC=83 (84 MHz/84 = 1 us/tick), ARR=1110,
 *     SMCR=0x54 (reset mode TS=TI1FP1), CCMR1=0x201 (CH1 direct TI1 falling + CH2 indirect TI1
 *     rising, no filter/prescaler), CCR3=1100 (no-edge heartbeat), CCER=0x13, DIER=0x0A
 *     (CC1IE|CC3IE), CR1=0x81 (CEN|ARPE). No EGR/UG forced.
 *   TIM4 ISR 0x08088ACE : UIF overflow -> read PD12 (high->duty 0 / low->duty 1000, period 0);
 *     CC1IF&CC2IF -> CCR1=period us, CCR2=low-time, validity CCR1 in [950,1050] && CCR2<=CCR1,
 *     duty = 1000*CCR2/CCR1 (per-mille = percent x10); hold-flag re-publish after disturbance.
 *   publish 0x08088A20 : 16-sample median-of-9 (span<=15) + DC deglitch (0 needs 128 samples,
 *     1000 needs 32) -> raw word (period<<16)|duty.
 *   median 0x08088B9E : insertion-sort-by-duty buf 0x200226E0[16], lowest tight 9-cluster middle,
 *     rejects duty 0/1000 (deglitch handles DC).
 *   globals: duty x10 @0x20000A00, period us @0x200009FE (NOT Hz — f_Hz = 1e6/period implicit).
 *
 * MEASUREMENT ONLY — captures the CP PWM, drives NO power pin. PD12 is configured AF input
 * (read-modify-write preserves the gpio_safe PD11/PD8/PD3 de-asserted states). The pure signal
 * chain (median/publish/process) is host-tested (test_cp_capture.c); the TIM4/GPIO/NVIC register
 * init + ISR wrapper are disasm-verified (verify_ccs2.py). Power-stage drive stays GATED.
 */
#ifndef CP_CAPTURE_H
#define CP_CAPTURE_H
#include <stdint.h>

/* CP capture state (mirrors stock CP struct 0x200009F8 + median buffer 0x200226E0). */
typedef struct {
    uint8_t  changed;        /* +0  changed flag (rd-clr getter)            */
    uint8_t  hold;           /* +1  hold/ready flag (re-publish after disturb) */
    uint8_t  deglitch_st;    /* +2  deglitch state 0/1/2                    */
    uint8_t  median_cnt;     /* +3  median sample count 0..16               */
    uint8_t  deglitch_cnt;   /* +4  deglitch consecutive-sample counter     */
    uint16_t period;         /* +6  PWM period in us (raw CCR1) — NOT Hz    */
    uint16_t duty;           /* +8  duty per-mille (percent x10; 50 = 5.0%) */
    uint32_t upd_count;      /* +C  update counter                          */
    uint32_t raw_word;       /* +10 filtered (period<<16)|duty              */
    uint32_t median_buf[16]; /* median buffer (lo half=duty, hi half=period) */
} cp_capture_t;

/* Byte-exact capture constants (C013 TIM4 init 0x08088A8C / ISR 0x08088ACE). */
#define CP_TIM4_PSC        83u     /* 0x53 — 84 MHz/(83+1) = 1 MHz -> 1 us/tick */
#define CP_TIM4_ARR        1110u   /* 0x456 — free-run overflow (us)            */
#define CP_TIM4_CCR3       1100u   /* 0x44C — no-edge heartbeat compare         */
#define CP_TIM4_SMCR       0x54u   /* reset mode, TS=TI1FP1                     */
#define CP_TIM4_CCMR1      0x201u  /* CC1S=01 direct TI1, CC2S=10 indirect TI1  */
#define CP_TIM4_CCER       0x13u   /* CC1E|CC1P (falling), CC2E (rising)        */
#define CP_TIM4_DIER       0x0Au   /* CC1IE | CC3IE                             */
#define CP_TIM4_CR1        0x81u   /* CEN | ARPE                                */
#define CP_CAP_VALID_LO    950u    /* 0x3B6 — CCR1 validity window low          */
#define CP_CAP_VALID_SPAN  100u    /* 0x64  — CCR1 in [950,1050] (~952-1053 Hz) */
#define CP_CAP_FULL        1000u   /* 0x3E8 — per-mille full scale (100%)       */
#define CP_CAP_MEDIAN_N    16u     /* 0x10  — median batch size                 */
#define CP_CAP_MEDIAN_SPAN 15u     /* 0xF   — tight-cluster max duty span (1.5%)*/
#define CP_CAP_DEGLITCH_ZERO 128u  /* 0x80  — consecutive duty-0 to force 0     */
#define CP_CAP_DEGLITCH_FULL 32u   /* 0x20  — consecutive duty-1000 to force 1000*/

void cp_capture_init(void);   /* RCC GPIOD+TIM4, PD12 AF2 pull-up, TIM4 regs, NVIC IRQ30 */

/* Pure signal chain — byte-faithful to median 0x08088B9E / publish 0x08088A20 / ISR 0x08088ACE.
 * process() takes the hardware readings (SR snapshot, CCR1, CCR2, PD12 level) as arguments so
 * the whole chain is host-testable with synthetic capture inputs. */
uint32_t cp_capture_median(cp_capture_t *s, uint16_t duty, uint16_t period);
uint32_t cp_capture_publish(cp_capture_t *s, uint16_t duty, uint16_t period);
void cp_capture_process(cp_capture_t *s, uint32_t sr, uint32_t ccr1, uint32_t ccr2, uint32_t pd12);

const cp_capture_t *cp_capture_get(void);
uint16_t cp_capture_duty(void);        /* duty per-mille @0x20000A00 equivalent   */
uint16_t cp_capture_period(void);      /* period us @0x200009FE equivalent (NOT Hz)*/
uint8_t  cp_capture_changed(void);     /* rd-clr changed flag                     */
uint32_t cp_capture_update_count(void);

#endif /* CP_CAPTURE_H */