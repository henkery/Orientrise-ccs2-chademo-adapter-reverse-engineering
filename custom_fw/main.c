/* main.c — custom adapter app entry point.
 *
 * SAFETY: this is being built up in incremental, independently-testable layers toward a
 * safe CHAdeMO charge controller (REPORT §5.17–§5.21). The ASSERTED power-stage drive
 * (closing contactors / precharge / charge GPIO) is NOT implemented yet and stays GATED —
 * until it is added and bench-validated, the app never drives an asserted power pin, so all
 * contactors remain open and no HV can appear. gpio_safe_init() only drives DE-ASSERTED
 * (safe) levels; the IWDG key write is a harmless watchdog feed.
 *
 * Current stage: SAFE BOOTSTRAP + CAN1 MESSAGE LAYER + HV MEASUREMENT — restore SYSCLK
 * 168 MHz (rcc), drive every power-stage GPIO to its SAFE/de-asserted state (gpio, §5.5c —
 * contactors open, no HV), init the HV measurement front-end (hv/adc/spi4/nv_cal, §5.21 —
 * ADC1+ADC2 simultaneous PB0/PB1, TIM8-triggered DMA2 accumulation -> live_raw, factory cal
 * read from external SPI4 flash -> get_hv -> outvol), init CAN1 (500k) + the CHAdeMO message
 * layer (can/chademo, §5.8.2/§5.18 — RX H100/H101/H102 parse, periodic H108/H109 standby TX
 * with the measured outvol in H108 byte1-2), start the 100 Hz OS tick + 100 kHz timebase
 * (tick, §5.20), and run the periodic 100 Hz loop. A RAM `heartbeat` increments each tick for
 * SWD proof-of-life; hv_outvol/hv_raw/hv_adc_raw/hv_cal_ok are SWD-readable measurement results.
 * Still NO asserted power-stage drive (measurement + CAN reporting only).
 *
 * Next layers (see README): charge state machine + engagement guard + interlocks (§5.17) ->
 * H102 current control (§5.21) -> gated power-stage drive (LAST, behind a safety flag).
 */
#include <stdint.h>
#include "rcc.h"
#include "gpio.h"
#include "can.h"
#include "chademo.h"
#include "tick.h"
#include "hv.h"
#include "adc.h"

#define IWDG_KR   (*(volatile uint32_t *)0x40003000u)
#define IWDG_FEED 0x0000AAAAu

volatile uint32_t heartbeat = 0;   /* SWD proof-of-life (RAM only, no side effect) */

/* HV measurement results (SWD-readable; also reported in H108 byte1-2 over CAN). */
volatile int32_t hv_outvol  = 0;   /* get_hv()/10, volts                       */
volatile int32_t hv_raw     = 0;   /* get_hv(), decivolts                      */
volatile int32_t hv_adc_raw = 0;   /* live ADC differential accumulation       */
volatile uint32_t hv_cal_ok = 0;   /* 1 if a valid factory cal was read        */

static void enable_irq(void)
{
    __asm__ volatile ("cpsie i" ::: "memory");
}

void main(void)
{
    rcc_init();          /* HSE 8 MHz -> PLL 168 MHz; APB1 42 / APB2 84 MHz */
    gpio_safe_init();    /* all power pins -> SAFE/de-asserted (contactors open, no HV) */
    hv_cal_ok = (hv_init() == 0);  /* SPI4 + factory cal + ADC1/2/DMA2/TIM8 front-end (§5.21) */
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

        /* HV measurement (§5.21): the ADC front-end accumulates live_raw in its DMA ISR;
         * get_hv interpolates it against the factory cal. Publish for SWD + CAN reporting.
         * MEASUREMENT ONLY — still no asserted power-stage drive. */
        hv_adc_raw = adc_get_live_raw();
        hv_raw     = hv_get_raw();
        hv_outvol  = hv_get_outvol();
        chademo_set_outvol(hv_outvol);   /* H108 byte1-2 = measured volts (450 clamp) */

        chademo_rx_process(now);   /* parse H100/H101/H102 from the CAN RX ring */
        chademo_tx_periodic(now);  /* H108/H109 standby report every 100 ms     */
        can_service();             /* bus-off recovery / error check            */
        /* (future: charge stm + engagement guard + interlocks, §5.17) */

        next++;                              /* advance one 10 ms tick */
        while ((int32_t)(tick_get() - next) < 0) { }
    }
}