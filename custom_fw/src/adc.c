/* adc.c — HV measurement ADC front-end (REPORT §5.21 measurement addendum).
 *
 * Faithful, byte-derived replica of the stock HV acquisition chain (C013):
 *   ADC init 0x08088584:
 *     - ADC1 (0x40012000): 8x channel 8 (PB0), CR1=0x800 (discontinuous, 1 conv/trigger),
 *       CR2=0x1E000001 (ADON + EXTSEL=14 TIM8_TRGO + rising edge), SMPR1=0x04924924,
 *       SMPR2=0x24924924, SQR1/2/3=0x00742108/0x10842108/0x10842108.
 *     - ADC2 (0x40012100): 8x channel 9 (PB1), same CR1/CR2/SMPR,
 *       SQR1/2/3=0x0074A529/0x1294A529/0x1294A529.
 *     - ADC common CCR=0x2A006: MULTI=6 (regular simultaneous ADC1+ADC2), DMA mode 2
 *       (32-bit CDR), ADCPRE=/6 (84 MHz/6 = 14 MHz ADC clock).
 *     - DMA2 stream0 ch0: circular, 32-bit, MINC, NDTR=16, PAR=ADC_CDR (0x40012308),
 *       M0AR=buffer, CR=0x5518 (TCIE+HTIE), enabled last.
 *     - TIM8 (0x40010400): PSC=0, ARR=0x53F (1343), CR2=0x20 (TRGO=update), CR1=0x95
 *       -> 168 MHz/1344 = 125 kHz conversion trigger.
 *   DMA ISR 0x080886BC + accumulator 0x08088748:
 *     - on HTIF0 process words 0..7, on TCIF0 words 8..15 (8 dual-samples per half);
 *     - per half compute sum(ADC1 low16) - sum(ADC2 high16)  (PB0 - PB1 differential);
 *     - accumulate; after 3125 half-buffer events (= 25000 samples, ~200 ms) publish the
 *       accumulated sum as live_raw and reset. get_hv interpolates live_raw directly.
 *
 * MEASUREMENT ONLY — this drives no power pin. ADC3 / DMA2 stream1 (CP/PP analog) and the
 * Vrefint-calibrated power-stage-monitor path (cal+0xC, thresholds 8000/10500) are separate
 * stock functions, decoded in REPORT but not needed for get_hv; they belong to later layers.
 */
#include "adc.h"

#define RCC_AHB1ENR   (*(volatile uint32_t *)0x40023830u)
#define RCC_APB2ENR   (*(volatile uint32_t *)0x40023844u)
#define NVIC_ISER1    (*(volatile uint32_t *)0xE000E104u)
#define GPIOB_BASE    0x40020400u
#define ADC1_BASE     0x40012000u
#define ADC2_BASE     0x40012100u
#define ADC_COM_BASE  0x40012300u
#define DMA2_BASE     0x40026400u
#define TIM8_BASE     0x40010400u
#define REG(b, o)     (*(volatile uint32_t *)((b) + (o)))

#define ADC_SR(b)     REG(b, 0x00u)
#define ADC_CR1(b)    REG(b, 0x04u)
#define ADC_CR2(b)    REG(b, 0x08u)
#define ADC_SMPR1(b)  REG(b, 0x0Cu)
#define ADC_SMPR2(b)  REG(b, 0x10u)
#define ADC_SQR1(b)   REG(b, 0x2Cu)
#define ADC_SQR2(b)   REG(b, 0x30u)
#define ADC_SQR3(b)   REG(b, 0x34u)
#define ADC_CCR       REG(ADC_COM_BASE, 0x04u)
#define ADC_CDR       REG(ADC_COM_BASE, 0x08u)

#define DMA2_LISR     REG(DMA2_BASE, 0x00u)
#define DMA2_LIFCR    REG(DMA2_BASE, 0x08u)
#define DMA2_S0CR     REG(DMA2_BASE, 0x10u)
#define DMA2_S0NDTR   REG(DMA2_BASE, 0x14u)
#define DMA2_S0PAR    REG(DMA2_BASE, 0x18u)
#define DMA2_S0M0AR   REG(DMA2_BASE, 0x1Cu)
#define DMA2_S0FCR    REG(DMA2_BASE, 0x24u)
#define DMA_LIFCR_S0  0x3Du               /* clear stream0 FE/DME/TE/HT/TC flags */
#define DMA_LISR_TCIF0 (1u << 5)

#define ACCUM_EVENTS  3125u               /* 0xC35 half-buffer events -> 25000 samples */

static volatile uint32_t dma_buf[16];     /* ADC12 CDR circular buffer (dual-samples) */
static volatile int32_t live_raw;         /* published accumulated differential sum   */
static int32_t accum;
static uint32_t count;

void adc_init(void)
{
    live_raw = 0; accum = 0; count = 0;

    RCC_AHB1ENR |= (1u << 1) | (1u << 22);          /* GPIOB, DMA2 */
    RCC_APB2ENR |= (1u << 8) | (1u << 9) | (1u << 1); /* ADC1, ADC2, TIM8 */
    (void)RCC_AHB1ENR; (void)RCC_APB2ENR;

    /* PB0 / PB1 analog mode, no pull. */
    REG(GPIOB_BASE, 0x00u) |= (3u << 0) | (3u << 2);
    REG(GPIOB_BASE, 0x0Cu) &= ~((3u << 0) | (3u << 2));

    /* DMA2 stream0: disable, clear flags, configure (EN=0 in 0x5518). */
    DMA2_S0CR = 0;
    while (DMA2_S0CR & 1u) { }
    DMA2_LIFCR = DMA_LIFCR_S0;
    DMA2_S0NDTR = 16u;
    DMA2_S0PAR  = (uint32_t)&ADC_CDR;     /* 0x40012308 */
    DMA2_S0M0AR = (uint32_t)dma_buf;
    DMA2_S0FCR  = 0;
    DMA2_S0CR   = 0x5518u;

    /* ADC common (preliminary), then ADC1 / ADC2 config — stock order. */
    ADC_CCR = 0x2A000u;

    ADC_CR1(ADC1_BASE) = 0; ADC_CR2(ADC1_BASE) = 0; ADC_SR(ADC1_BASE) = 0;
    ADC_SMPR1(ADC1_BASE) = 0x04924924u; ADC_SMPR2(ADC1_BASE) = 0x24924924u;
    ADC_SQR1(ADC1_BASE) = 0x00742108u; ADC_SQR2(ADC1_BASE) = 0x10842108u;
    ADC_SQR3(ADC1_BASE) = 0x10842108u;
    ADC_CR1(ADC1_BASE) = 0x800u; ADC_CR2(ADC1_BASE) = 0x1E000001u;

    ADC_CR1(ADC2_BASE) = 0; ADC_CR2(ADC2_BASE) = 0; ADC_SR(ADC2_BASE) = 0;
    ADC_SMPR1(ADC2_BASE) = 0x04924924u; ADC_SMPR2(ADC2_BASE) = 0x24924924u;
    ADC_SQR1(ADC2_BASE) = 0x0074A529u; ADC_SQR2(ADC2_BASE) = 0x1294A529u;
    ADC_SQR3(ADC2_BASE) = 0x1294A529u;
    ADC_CR1(ADC2_BASE) = 0x800u; ADC_CR2(ADC2_BASE) = 0x1E000001u;

    /* MULTI=6 regular simultaneous + DMA mode 2 + ADCPRE=/6. */
    ADC_CCR = 0x2A006u;

    DMA2_S0CR |= 1u;                      /* enable stream0 */

    /* TIM8 trigger: 168 MHz / (1343+1) = 125 kHz, TRGO = update. */
    REG(TIM8_BASE, 0x28u) = 0;            /* PSC */
    REG(TIM8_BASE, 0x2Cu) = 0x53Fu;       /* ARR */
    REG(TIM8_BASE, 0x10u) = 0;            /* SR  */
    REG(TIM8_BASE, 0x0Cu) = 0;            /* DIER */
    REG(TIM8_BASE, 0x04u) = 0x20u;        /* CR2: MMS=010 update TRGO */
    REG(TIM8_BASE, 0x00u) = 0x95u;        /* CR1: CEN+URS+DIR+ARPE */

    NVIC_ISER1 = (1u << 24);              /* DMA2_Stream0_IRQn = 56 (56-32=24) */
}

int32_t adc_get_live_raw(void)
{
    return live_raw;
}

void DMA2_Stream0_IRQHandler(void)
{
    uint32_t isr = DMA2_LISR;
    DMA2_LIFCR = DMA_LIFCR_S0;

    /* TCIF0 set -> second half (words 8..15) just completed; else first half (0..7). */
    uint32_t base = (isr & DMA_LISR_TCIF0) ? 8u : 0u;
    int32_t diff = 0;
    for (uint32_t i = 0; i < 8u; i++) {
        uint32_t w = dma_buf[base + i];   /* low16 = ADC1 (PB0), high16 = ADC2 (PB1) */
        diff += (int32_t)(w & 0xFFFFu) - (int32_t)(w >> 16);
    }

    accum += diff;
    if (++count >= ACCUM_EVENTS) {
        live_raw = accum;
        accum = 0;
        count = 0;
    }
}
