/* main.c — custom adapter app entry point.
 *
 * SAFETY: this is being built up in incremental, independently-testable layers toward a
 * safe CHAdeMO charge controller (REPORT §5.17–§5.21). The ASSERTED power-stage drive
 * (closing contactors / precharge / charge GPIO) is NOT implemented yet and stays GATED —
 * until it is added and bench-validated, the app never drives an asserted power pin, so all
 * contactors remain open and no HV can appear. gpio_safe_init() only drives DE-ASSERTED
 * (safe) levels; the IWDG key write is a harmless watchdog feed.
 *
 * Current stage: SAFE BOOTSTRAP + CAN1 MESSAGE LAYER — restore SYSCLK 168 MHz (rcc), drive
 * every power-stage GPIO to its SAFE/de-asserted state (gpio, §5.5c — contactors open, no HV),
 * init CAN1 (500k) + the CHAdeMO message layer (can/chademo, §5.8.2/§5.18 — RX H100/H101/H102
 * parse, periodic H108/H109 standby TX), start the 100 Hz OS tick + 100 kHz timebase (tick,
 * §5.20), and run the periodic 100 Hz loop. A RAM `heartbeat` increments each tick for SWD
 * proof-of-life. Still NO asserted power-stage drive (CAN reporting only).
 *
 * Next layers (see README): ADC/get_hv measurement (§5.21) -> charge state machine +
 * engagement guard + interlocks (§5.17) -> H102 current control (§5.21) -> gated power-stage
 * drive (LAST, behind a safety flag).
 */
#include <stdint.h>
#include "rcc.h"
#include "gpio.h"
#include "can.h"
#include "chademo.h"
#include "tick.h"

#define IWDG_KR   (*(volatile uint32_t *)0x40003000u)
#define IWDG_FEED 0x0000AAAAu

volatile uint32_t heartbeat = 0;   /* SWD proof-of-life (RAM only, no side effect) */

static void enable_irq(void)
{
    __asm__ volatile ("cpsie i" ::: "memory");
}

void main(void)
{
    rcc_init();          /* HSE 8 MHz -> PLL 168 MHz; APB1 42 / APB2 84 MHz */
    gpio_safe_init();    /* all power pins -> SAFE/de-asserted (contactors open, no HV) */
    can_init();          /* CAN1 500k + acceptance filter + RX0 interrupt (NVIC)     */
    chademo_init();      /* zero the vehicle-data struct + watchdog timestamps       */
    tick_init();         /* 100 Hz SysTick OS tick + 100 kHz TIM2 timebase   */
    enable_irq();        /* boot jumped with interrupts masked (cpsid i)     */

    uint32_t next = tick_get();
    for (;;) {
        IWDG_KR = IWDG_FEED;   /* keep watchdog happy; no-op if disabled */
        heartbeat++;           /* 100 Hz proof-of-life counter           */

        /* --- periodic 100 Hz control step --- */
        uint32_t now = tick_get();
        chademo_rx_process(now);   /* parse H100/H101/H102 from the CAN RX ring */
        chademo_tx_periodic(now);  /* H108/H109 standby report every 100 ms     */
        can_service();             /* bus-off recovery / error check            */
        /* (future: charge stm + engagement guard + interlocks, §5.17) */

        next++;                              /* advance one 10 ms tick */
        while ((int32_t)(tick_get() - next) < 0) { }
    }
}