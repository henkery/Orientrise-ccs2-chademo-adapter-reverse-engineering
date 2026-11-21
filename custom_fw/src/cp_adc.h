/* cp_adc.h — CP/PP analog ADC3 acquisition front-end (REPORT §5.9, Agent I / analyze95).
 *
 * Faithful, byte-derived INERT replica of the C013 CP/PP analog acquisition chain that feeds the
 * CP/PP signaling logic (cp.c) and the charge-stm plug-in input. MEASUREMENT ONLY — drives no
 * power pin. Shares the TIM8 125 kHz TRGO timebase + ADC common clock (ADCPRE=/6 -> 14 MHz) that
 * adc.c (HV ADC1+ADC2) already configures; this layer adds ADC3 + DMA2 Stream1.
 *
 * Stock chain (C013 ADC init 0x08088584, CP/PP block 0x08088628; ISR 0x0808876A IRQ57):
 *   ADC3 (0x40012200) CR1=0x800 (DISCEN, ONE conversion per trigger), CR2=0x1E000301
 *     (ADON|DMA|DDS|EXTSEL=14 TIM8_TRGO|EXTEN rising), 12-bit, SMPR1=0x04924924 /
 *     SMPR2=0x24924924 (84-cycle sampling all channels), sequence SQ1..8 (L=7):
 *       SQR1=0x00700581 SQR2=0x04110401 SQR3=0x18110441 -> [ch1,ch2,ch1,ch2,ch1,ch12,ch1,ch0]
 *     pins: ch1=PA1, ch2=PA2, ch12=PC2, ch0=PA0 (MODER-proven analog).
 *   DMA2 Stream1 Channel2 (0x40026428): CR=0x04002D10|EN (TCIE only, HTIE=0, CIRC, MINC,
 *     halfword x halfword, CHSEL=2), NDTR=16 halfwords, PAR=0x4001224C (ADC3_DR),
 *     M0AR=buffer, FCR=0. TC every 16 conversions = 2 sequences = 128 us.
 *   ISR 0x0808876A sums the SECOND buffer half (HTIE=0 -> always second half in practice; the
 *     first-half mirror is defensive), accumulates, publishes every 8 TC events (= 1.024 ms):
 *       PP  raw = accA = sum_8events (ch2_SQ2 + ch2_SQ4) = 16*sum(ch2)   [PA2 ONLY]
 *       BAT raw = accB = sum_8events ch12_SQ6            = 8*sum(ch12)   [PC2]
 *       CPD raw = accC = sum_8events ch0_SQ8             = 8*sum(ch0)    [PA0]
 *     then clears accA/accB/accC + the event counter. The 4*ch1 sum (PA1) is a SEPARATE byproduct
 *     (stock struct +0xC, the calibrated "+24V" rail reading + power-fail hysteresis) — it is NOT
 *     folded into PP. (CORRECTION to Agent I's summary "PP=32*ch1+16*ch2": the ISR bytes accumulate
 *     only 2*ch2 into accA; r5=4*ch1 feeds the +0xC byproduct store, never accA. analyze95 proves it.)
 *   getters (mV, integer udiv truncation):
 *       AD_PP  0x08088850 = PP_raw  * 3300 / 65520   (65520 = 16*4095)
 *       AD_BAT 0x08088864 = BAT_raw * 6600 / 32760   (32760 = 8*4095; x2 external range)
 *       AD_CPD 0x08088878 = CPD_raw * 3300 / 32760
 *   digital reads (filterless leaves):
 *       D_LINK 0x080884BA = GPIOB_IDR bit12 (PB12 IN pull-down, PLC modem link status)
 *       PD11   0x08088B88 = GPIOD_IDR bit11 (PD11 is an OUTPUT driven by stock BCB 0x080528DC;
 *              this layer only READS it back — the BCB drive stays GATED, measurement only)
 *
 * The power-fail hysteresis + event queue (stock struct +0x01 flag / +0x30 queue) and the SPI4
 * calibration page-2 "+24V" scaling are a separate subsystem (Agent I §8 boundary) — dropped here
 * for the inert measurement layer; the 4*ch1 byproduct is still recorded for SWD readout.
 *
 * Pure accumulation/publish + scaling helpers are host-tested (test_cp_adc.c). Hardware init /
 * ISR / GPIO reads are disasm-verified (verify_ccs2.py).
 */
#ifndef CP_ADC_H
#define CP_ADC_H
#include <stdint.h>

/* ADC3 register-exact init constants (C013 0x08088628 block). */
#define CP_ADC3_BASE      0x40012200u
#define CP_ADC3_CR1       0x00000800u   /* DISCEN, 1 conv/trigger, 12-bit */
#define CP_ADC3_CR2       0x1E000301u   /* ADON|DMA|DDS|EXTSEL=14 TIM8_TRGO|rising */
#define CP_ADC3_SMPR1     0x04924924u   /* 84-cycle sampling all channels */
#define CP_ADC3_SMPR2     0x24924924u
#define CP_ADC3_SQR1      0x00700581u   /* L=7 -> 8 conversions */
#define CP_ADC3_SQR2      0x04110401u
#define CP_ADC3_SQR3      0x18110441u   /* SQ1..6 = ch1,ch2,ch1,ch2,ch1,ch12 */
#define CP_ADC_CCR        0x0002A006u   /* MULTI=6 (ADC12) + DMA mode2 + ADCPRE=/6 (14 MHz) */
#define CP_DMA_S1CR       0x04002D10u   /* CHSEL=2|halfword|MINC|CIRC|TCIE (EN added later) */
#define CP_DMA_NDTR       16u           /* halfwords = 2 sequences */
#define CP_DMA_LIFCR_S1   0x00000F40u   /* clear stream1 FE/DME/TE/HT/TC flags */
#define CP_DMA_LISR_TCIF1 (1u << 11)
#define CP_ADC_PUBLISH_N  8u            /* publish every 8 TC events = 1.024 ms */

/* Published-data + accumulator state (mirrors stock struct 0x200009C0 CP/PP fields). */
typedef struct {
    uint32_t pp_raw;     /* +0x10 published PP  = 16*sum(ch2)  */
    uint32_t bat_raw;    /* +0x18 published BAT = 8*sum(ch12)  */
    uint32_t cpd_raw;    /* +0x20 published CPD = 8*sum(ch0)   */
    uint32_t accA;       /* +0x14 PP accumulator               */
    uint32_t accB;       /* +0x1C BAT accumulator              */
    uint32_t accC;       /* +0x24 CPD accumulator              */
    uint32_t ch1x4;      /* +0x0C last-event 4*ch1 byproduct (+24V / power-fail) */
    uint8_t  count;      /* +0x00 TC event counter (0..8)      */
} cp_adc_t;

void cp_adc_init(void);

/* Pure per-event accumulation + publish-every-8 (host-testable). `half` points at the 8 halfwords
 * of the just-completed sequence (SQ1..8 = [ch1,ch2,ch1,ch2,ch1,ch12,ch1,ch0]). Updates s. */
void cp_adc_publish(cp_adc_t *s, const uint16_t *half);

/* Pure scaling getters (byte-exact mV, udiv truncation). */
uint16_t cp_adc_pp_mv(uint32_t raw);    /* raw*3300/65520 */
uint16_t cp_adc_bat_mv(uint32_t raw);   /* raw*6600/32760 */
uint16_t cp_adc_cpd_mv(uint32_t raw);   /* raw*3300/32760 */

/* Published raw words (SWD-readable; fit uint16_t: PP<=65520, BAT/CPD<=32760). */
uint32_t cp_adc_pp_raw(void);
uint32_t cp_adc_bat_raw(void);
uint32_t cp_adc_cpd_raw(void);
uint32_t cp_adc_ch1x4(void);            /* last 4*ch1 byproduct (PA1, +24V rail) */

/* Filterless digital reads (measurement only — no GPIO drive). */
uint8_t cp_adc_d_link(void);            /* GPIOB_IDR bit12 (PB12 PLC link) */
uint8_t cp_adc_pd11(void);              /* GPIOD_IDR bit11 (BCB state read-back) */

#endif /* CP_ADC_H */
