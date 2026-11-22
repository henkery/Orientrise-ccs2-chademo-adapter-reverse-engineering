/* gpio.c — power-stage GPIO safe-state init (REPORT §5.5c / §5.17).
 *
 * Glitch-free safe bootstrap: while the pins are still in their reset state (input), pre-load
 * each port's output latch to the SAFE level via BSRR, THEN switch MODER to general-purpose
 * output. The pin therefore starts driving the de-asserted level the instant it becomes an
 * output — an asserted (contactor-closing) level is never driven, even for a cycle.
 *
 * Safe levels (byte-derived active levels, see gpio.h):
 *   active-HIGH pins -> LOW  : PE7, PE8 (CHAdeMO d1/d2), PD8 (BatteryPower), PB10/PB11 (PreCharge)
 *   active-LOW  pins -> HIGH : PC9 (BatteryCharge), PD3 + PE4 (e-lock motor)
 *
 * Board power-hold / status (NOT power-stage): PB14 + PE15 are driven HIGH at boot exactly as the
 * stock GPIO init does (analyze74: PB14 OUT lvl1, PE15 OUT PU lvl1). The stock firmware asserts these
 * to latch the board power rail on (power-hold) and drive the status LED; leaving them floating (the
 * prior custom init) let the power IC drop the rail ~1 s after boot, so the app never stayed up long
 * enough to enumerate USB. Matching the stock HIGH state is safe — neither pin gates a contactor,
 * precharge, or charge path.
 *
 * OTYPER/OSPEEDR/PUPDR are left at reset defaults (push-pull / low-speed / no-pull), which is
 * correct for relay/contactor drive. Runs with interrupts masked (before enable_irq in main).
 */
#include "gpio.h"

#define RCC_AHB1ENR  (*(volatile uint32_t *)0x40023830u)
#define GPIOB_BASE   0x40020400u
#define GPIOC_BASE   0x40020800u
#define GPIOD_BASE   0x40020C00u
#define GPIOE_BASE   0x40021000u

#define MODER(b)     (*(volatile uint32_t *)((b) + 0x00u))
#define BSRR(b)      (*(volatile uint32_t *)((b) + 0x18u))

/* BSRR helpers: set pin n (drive HIGH) = bit n; reset pin n (drive LOW) = bit n+16. */
#define SET(n)       (1u << (n))
#define RESET(n)     (1u << ((n) + 16u))
/* MODER: 2 bits/pin, 01 = general-purpose output. */
#define OUT_MASK(n)  (3u << (2u * (n)))
#define OUT_VAL(n)   (1u << (2u * (n)))

void gpio_safe_init(void)
{
    /* Enable GPIO B/C/D/E clocks (AHB1ENR bits 1..4). */
    RCC_AHB1ENR |= (1u << 1) | (1u << 2) | (1u << 3) | (1u << 4);
    (void)RCC_AHB1ENR;   /* short delay after clock enable before register access */

    /* 1) Pre-load safe output latches (pins still reset-state inputs). */
    BSRR(GPIOB_BASE) = RESET(10) | RESET(11) | SET(14);       /* PB10/PB11 LOW (precharge open); PB14 HIGH (power-hold/LED, stock) */
    BSRR(GPIOC_BASE) = SET(9);                                /* PC9 HIGH (charge off, active-low) */
    BSRR(GPIOD_BASE) = SET(3) | RESET(8);                     /* PD3 HIGH (e-lock off), PD8 LOW (contactor open) */
    BSRR(GPIOE_BASE) = SET(4) | RESET(7) | RESET(8) | SET(15);/* PE4 HIGH (e-lock off), PE7/PE8 LOW (CHAdeMO off); PE15 HIGH (power-hold/LED, stock) */

    /* 2) Switch each power pin to general-purpose output; it now drives the safe latch. */
    MODER(GPIOB_BASE) = (MODER(GPIOB_BASE) & ~(OUT_MASK(10) | OUT_MASK(11) | OUT_MASK(14)))
                        | OUT_VAL(10) | OUT_VAL(11) | OUT_VAL(14);
    MODER(GPIOC_BASE) = (MODER(GPIOC_BASE) & ~OUT_MASK(9)) | OUT_VAL(9);
    MODER(GPIOD_BASE) = (MODER(GPIOD_BASE) & ~(OUT_MASK(3) | OUT_MASK(8)))
                        | OUT_VAL(3) | OUT_VAL(8);
    MODER(GPIOE_BASE) = (MODER(GPIOE_BASE) & ~(OUT_MASK(4) | OUT_MASK(7) | OUT_MASK(8) | OUT_MASK(15)))
                        | OUT_VAL(4) | OUT_VAL(7) | OUT_VAL(8) | OUT_VAL(15);
}
