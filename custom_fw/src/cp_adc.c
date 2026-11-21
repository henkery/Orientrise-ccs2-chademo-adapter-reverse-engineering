/* cp_adc.c — CP/PP analog ADC3 acquisition front-end (REPORT §5.9, Agent I / analyze95).
 *
 * Faithful, byte-derived INERT replica of the C013 CP/PP analog acquisition chain. MEASUREMENT
 * ONLY — drives no power pin. Shares the TIM8 125 kHz TRGO + ADC common clock (ADCPRE=/6) that
 * adc.c (HV ADC1+ADC2) configures; this layer adds ADC3 (ch0/1/2/12) + DMA2 Stream1 Channel2.
 *
 * Stock ADC init 0x08088584 CP/PP block 0x08088628 (register writes IN ORDER):
 *   ADC_CCR=0x0002A006; DMA2_Stream1 (0x40026428): CR=0 wait EN clear, LIFCR=0xF40, NDTR=16,
 *   PAR=0x4001224C (ADC3_DR), M0AR=buf, FCR=0, CR=0x04002D10; ADC3 (0x40012200): CR1=0, CR2=0,
 *   SR=0, SMPR1=0x04924924, SMPR2=0x24924924, SQR1=0x00700581, SQR2=0x04110401,
 *   SQR3=0x18110441, CR1=0x800 (DISCEN), CR2=0x1E000301; then S1CR|=1. TIM8 (PSC=0, ARR=0x53F,
 *   CR2=0x20, CR1=0x95 -> 125 kHz TRGO) is shared with the HV path and owned by adc.c.
 *
 * ISR 0x0808876A (IRQ57): clear stream1 flags, sum the SECOND buffer half (TCIF1; HTIE=0 so the
 *   first-half mirror is defensive dead code), accumulate per event:
 *     accA += ch2_SQ2 + ch2_SQ4   (2*ch2 -> PP, PA2 ONLY)
 *     accB += ch12_SQ6            (BAT, PC2)
 *     accC += ch0_SQ8             (CPD, PA0)
 *     ch1x4 = ch1_SQ1+SQ3+SQ5+SQ7 (4*ch1 byproduct -> +24V rail / power-fail, NOT folded into PP)
 *   every 8 TC events (= 1.024 ms) publish pp_raw=accA / bat_raw=accB / cpd_raw=accC and clear the
 *   accumulators + counter. CORRECTION to Agent I's summary "PP=32*ch1+16*ch2": the bytes accumulate
 *   only 2*ch2 into accA (PP=16*sum(ch2)); r5=4*ch1 feeds the +0xC byproduct store, never accA.
 *   The power-fail hysteresis + event queue are a separate subsystem (Agent I §8) — dropped here.
 *
 * Getters 0x08088850/64/78: AD_PP=raw*3300/65520, AD_BAT=raw*6600/32760, AD_CPD=raw*3300/32760.
 * D_LINK 0x080884BA = GPIOB_IDR bit12 (PB12); PD11 0x08088B88 = GPIOD_IDR bit11 (BCB read-back).
 */
#include "cp_adc.h"

#define RCC_AHB1ENR   (*(volatile uint32_t *)0x40023830u)
#define RCC_APB2ENR   (*(volatile uint32_t *)0x40023844u)
#define NVIC_ISER1    (*(volatile uint32_t *)0xE000E104u)
#define GPIOA_BASE    0x40020000u
#define GPIOB_BASE    0x40020400u
#define GPIOC_BASE    0x40020800u
#define GPIOD_BASE    0x40020C00u
#define ADC_COM_BASE  0x40012300u
#define DMA2_BASE     0x40026400u
#define REG(b, o)     (*(volatile uint32_t *)((b) + (o)))

#define ADC_SR(b)     REG(b, 0x00u)
#define ADC_CR1(b)    REG(b, 0x04u)
#define ADC_CR2(b)    REG(b, 0x08u)
#define ADC_SMPR1(b)  REG(b, 0x0Cu)
#define ADC_SMPR2(b)  REG(b, 0x10u)
#define ADC_SQR1(b)   REG(b, 0x2Cu)
#define ADC_SQR2(b)   REG(b, 0x30u)
#define ADC_SQR3(b)   REG(b, 0x34u)
#define ADC_DR(b)     REG(b, 0x4Cu)
#define ADC_CCR       REG(ADC_COM_BASE, 0x04u)

#define DMA2_LISR     REG(DMA2_BASE, 0x00u)
#define DMA2_LIFCR    REG(DMA2_BASE, 0x08u)
#define DMA2_S1CR     REG(DMA2_BASE, 0x28u)
#define DMA2_S1NDTR   REG(DMA2_BASE, 0x2Cu)
#define DMA2_S1PAR    REG(DMA2_BASE, 0x30u)
#define DMA2_S1M0AR   REG(DMA2_BASE, 0x34u)
#define DMA2_S1FCR    REG(DMA2_BASE, 0x3Cu)

static volatile uint16_t cp_dma_buf[16] __attribute__((aligned(4)));  /* ADC3 circular buffer */
static volatile cp_adc_t cadc;                                        /* published + accum state */

void cp_adc_publish(cp_adc_t *s, const uint16_t *half)
{
    /* SQ1..8 = [ch1, ch2, ch1, ch2, ch1, ch12, ch1, ch0]. */
    uint32_t ch1x4 = (uint32_t)half[0] + half[2] + half[4] + half[6];  /* 4*ch1 byproduct (PA1) */
    s->accA += (uint32_t)half[1] + half[3];   /* 2*ch2 -> PP (PA2 only; NOT ch1) */
    s->accB += half[5];                       /* ch12 -> BAT (PC2) */
    s->accC += half[7];                       /* ch0 -> CPD (PA0) */
    s->ch1x4 = ch1x4;
    if (++s->count >= CP_ADC_PUBLISH_N) {
        s->pp_raw  = s->accA;
        s->bat_raw = s->accB;
        s->cpd_raw = s->accC;
        s->accA = 0; s->accB = 0; s->accC = 0;
        s->count = 0;
    }
}

uint16_t cp_adc_pp_mv(uint32_t raw)  { return (uint16_t)((raw * 3300u) / 65520u); }
uint16_t cp_adc_bat_mv(uint32_t raw) { return (uint16_t)((raw * 6600u) / 32760u); }
uint16_t cp_adc_cpd_mv(uint32_t raw) { return (uint16_t)((raw * 3300u) / 32760u); }

uint32_t cp_adc_pp_raw(void)  { return cadc.pp_raw; }
uint32_t cp_adc_bat_raw(void) { return cadc.bat_raw; }
uint32_t cp_adc_cpd_raw(void) { return cadc.cpd_raw; }
uint32_t cp_adc_ch1x4(void)   { return cadc.ch1x4; }

uint8_t cp_adc_d_link(void) { return (uint8_t)((REG(GPIOB_BASE, 0x10u) >> 12) & 1u); }
uint8_t cp_adc_pd11(void)   { return (uint8_t)((REG(GPIOD_BASE, 0x10u) >> 11) & 1u); }

void cp_adc_init(void)
{
    cadc.pp_raw = 0; cadc.bat_raw = 0; cadc.cpd_raw = 0;
    cadc.accA = 0; cadc.accB = 0; cadc.accC = 0; cadc.ch1x4 = 0; cadc.count = 0;

    RCC_AHB1ENR |= (1u << 0) | (1u << 2) | (1u << 22);   /* GPIOA, GPIOC, DMA2 */
    RCC_APB2ENR |= (1u << 10) | (1u << 1);               /* ADC3, TIM8 (shared w/ adc.c) */
    (void)RCC_AHB1ENR; (void)RCC_APB2ENR;

    /* PA0/PA1/PA2 (ADC3 ch0/ch1/ch2) + PC2 (ch12) analog mode, no pull. RMW preserves the
     * other pins (gpio_safe states). MODER bits 0/2/4 (GPIOA) and bit 4 (GPIOC) -> 0b11. */
    REG(GPIOA_BASE, 0x00u) = (REG(GPIOA_BASE, 0x00u) & ~0x3Fu) | 0x3Fu;
    REG(GPIOA_BASE, 0x0Cu) &= ~0x3Fu;
    REG(GPIOC_BASE, 0x00u) = (REG(GPIOC_BASE, 0x00u) & ~0x30u) | 0x30u;
    REG(GPIOC_BASE, 0x0Cu) &= ~0x30u;

    /* ADC common final CCR (ADCPRE=/6 -> 14 MHz; MULTI=6/DMA2 inert for ADC3). adc.c already
     * wrote this for the HV path; rewrite byte-faithful to the CP/PP block's final store. */
    ADC_CCR = CP_ADC_CCR;

    /* DMA2 Stream1 Channel2: disable, clear flags, configure (EN=0 in 0x04002D10). */
    DMA2_S1CR = 0;
    while (DMA2_S1CR & 1u) { }
    DMA2_LIFCR  = CP_DMA_LIFCR_S1;
    DMA2_S1NDTR = CP_DMA_NDTR;
    DMA2_S1PAR  = (uint32_t)&ADC_DR(CP_ADC3_BASE);   /* 0x4001224C */
    DMA2_S1M0AR = (uint32_t)cp_dma_buf;
    DMA2_S1FCR  = 0;
    DMA2_S1CR   = CP_DMA_S1CR;

    /* ADC3 config — stock order. */
    ADC_CR1(CP_ADC3_BASE) = 0; ADC_CR2(CP_ADC3_BASE) = 0; ADC_SR(CP_ADC3_BASE) = 0;
    ADC_SMPR1(CP_ADC3_BASE) = CP_ADC3_SMPR1; ADC_SMPR2(CP_ADC3_BASE) = CP_ADC3_SMPR2;
    ADC_SQR1(CP_ADC3_BASE) = CP_ADC3_SQR1; ADC_SQR2(CP_ADC3_BASE) = CP_ADC3_SQR2;
    ADC_SQR3(CP_ADC3_BASE) = CP_ADC3_SQR3;
    ADC_CR1(CP_ADC3_BASE) = CP_ADC3_CR1;   /* DISCEN, 1 conv/trigger */
    ADC_CR2(CP_ADC3_BASE) = CP_ADC3_CR2;   /* ADON|DMA|DDS|TIM8_TRGO rising */

    DMA2_S1CR |= 1u;                       /* enable stream1 */

    /* TIM8 125 kHz TRGO is shared with the HV path and already running (adc.c). */
    NVIC_ISER1 = (1u << 25);               /* DMA2_Stream1_IRQn = 57 (57-32=25) */
}

void DMA2_Stream1_IRQHandler(void)
{
    uint32_t lisr = DMA2_LISR;
    DMA2_LIFCR = CP_DMA_LIFCR_S1;

    /* TCIF1 set -> second half (halfwords 8..15) just completed; else first half (0..7).
     * HTIE=0 so in practice always the second half (the first-half path is defensive). */
    const volatile uint16_t *src = cp_dma_buf + ((lisr & CP_DMA_LISR_TCIF1) ? 8u : 0u);
    uint16_t half[8];
    for (uint32_t i = 0; i < 8u; i++) half[i] = src[i];
    cp_adc_publish((cp_adc_t *)&cadc, half);
}
