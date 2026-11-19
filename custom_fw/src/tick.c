/* tick.c — 100 Hz OS tick (SysTick ISR) + 100 kHz free-running TIM2 counter (§5.20).
 * The stock OS tick is 100 Hz (10 ms); the stm timeouts count 10 ms units. We use SysTick
 * with TICKINT for the OS tick (the stock's SysTick is a free-running timestamp; using it
 * for the periodic tick is a deliberate custom-design choice). TIM2 reproduces the stock
 * 100 kHz timebase: PSC=839 (84 MHz APB1 timer clock / 840), ARR=0xFFFF, free-running.
 */
#include "tick.h"
#include "rcc.h"

/* SysTick (Cortex-M4 core) */
#define SYST_CSR   (*(volatile uint32_t *)0xE000E010u)
#define SYST_RVR   (*(volatile uint32_t *)0xE000E014u)
#define SYST_CVR   (*(volatile uint32_t *)0xE000E018u)
#define SYST_ENABLE   (1u << 0)
#define SYST_TICKINT  (1u << 1)
#define SYST_CLKSRC   (1u << 2)   /* processor clock (168 MHz) */

/* TIM2 (APB1, 0x40000000) */
#define TIM2_BASE  0x40000000u
#define TIM2_CR1   (*(volatile uint32_t *)(TIM2_BASE + 0x00u))
#define TIM2_EGR   (*(volatile uint32_t *)(TIM2_BASE + 0x14u))
#define TIM2_CNT   (*(volatile uint32_t *)(TIM2_BASE + 0x24u))
#define TIM2_PSC   (*(volatile uint32_t *)(TIM2_BASE + 0x28u))
#define TIM2_ARR   (*(volatile uint32_t *)(TIM2_BASE + 0x2Cu))
#define RCC_APB1ENR (*(volatile uint32_t *)0x40023840u)
#define RCC_APB1ENR_TIM2EN (1u << 0)

static volatile uint32_t tick_count;   /* 100 Hz software counter (10 ms units) */

void SysTick_Handler(void)
{
    tick_count++;
}

void tick_init(void)
{
    /* 100 Hz OS tick: reload = 168 MHz / 100 - 1 = 1 679 999 (0x19999F). */
    SYST_RVR = (SYSCLK_HZ / TICK_HZ) - 1u;
    SYST_CVR = 0u;
    SYST_CSR = SYST_ENABLE | SYST_TICKINT | SYST_CLKSRC;

    /* TIM2: 100 kHz free-running 16-bit counter (10 µs/tick). */
    RCC_APB1ENR |= RCC_APB1ENR_TIM2EN;
    (void)RCC_APB1ENR;
    TIM2_PSC = 839u;          /* 84 MHz / 840 = 100 kHz */
    TIM2_ARR = 0xFFFFu;       /* free-running */
    TIM2_EGR = 1u;            /* UG: load the prescaler */
    TIM2_CR1 = 1u;            /* CEN: enable */
}

uint32_t tick_get(void)
{
    return tick_count;
}

uint32_t tick_micros(void)
{
    /* 16-bit CNT at 10 µs/tick -> µs, wraps every 655 360 µs (~655 ms). */
    return (TIM2_CNT & 0xFFFFu) * US_PER_TICK;
}

void tick_delay_ms(uint32_t ms)
{
    uint32_t start = tick_count;
    uint32_t ticks = (ms + TICK_MS - 1u) / TICK_MS;
    while ((tick_count - start) < ticks) { }
}