/* main.c — INERT skeleton for the Orientrise KM-CCS2CHAdeMO-1 adapter custom app.
 *
 * SAFETY: this is a build/flash/recovery pipeline proof, NOT a charge controller.
 * It performs NO GPIO writes and enables NO peripheral that could energise the power
 * stage. All contactor / precharge / charge / e-lock pins stay at their reset state
 * (analog input, contactors open). The only peripheral touched is the IWDG key register
 * (a watchdog feed — harmless whether or not the watchdog is enabled).
 *
 * Behaviour: feed the IWDG, bump a RAM heartbeat counter, idle. If the bootloader left
 * the IWDG running, feeding it keeps the app alive (no reset loop); if it did not, the
 * feed is a no-op. The heartbeat lets you confirm "the custom app is running" over SWD
 * (read &heartbeat) without any external side effect.
 *
 * To grow this into a safe charge controller, implement the laws decoded in REPORT
 * §5.17 (state machine + engagement guard + interlocks), §5.18 (H108/H109 output),
 * §5.20 (100 Hz timebase) and §5.21 (get_hv measurement + H102 current control) on the
 * §5.19 memory layout — and only then drive the power-stage GPIO (§5.5c).
 */
#include <stdint.h>

/* IWDG key register (APB1, 0x40003000). IWDG has no RCC enable bit — it is always
 * accessible (LSI-clocked), so no clock init is needed to feed it. */
#define IWDG_KR   (*(volatile uint32_t *)0x40003000u)
#define IWDG_FEED 0x0000AAAAu

/* RAM heartbeat: increments each loop. Observable over SWD; no hardware side effect. */
volatile uint32_t heartbeat = 0;

static void idle_delay(volatile uint32_t n)
{
    while (n--) {
        __asm__ volatile ("nop");
    }
}

void main(void)
{
    for (;;) {
        IWDG_KR = IWDG_FEED;   /* keep the watchdog happy; no-op if disabled */
        heartbeat++;           /* proof-of-life counter (RAM only)         */
        idle_delay(200000);    /* ~ms-scale idle; far below any IWDG timeout */
    }
}