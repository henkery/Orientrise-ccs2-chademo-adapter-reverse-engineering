/* tick.h — firmware timebase for the custom adapter app (REPORT §5.20, analyze84).
 * Two layers, matching the decoded stock timebase:
 *   - 100 Hz OS tick (10 ms): a 32-bit software counter incremented by the SysTick ISR.
 *     All stm timeout/period constants are in these 10 ms units (engagement 250, state-17
 *     wait 424, CurrentDemand adjust 125, whole-bus watchdog 1525).
 *   - 100 kHz free-running counter (10 µs/tick): TIM2, PSC=839 (84 MHz/840), ARR=0xFFFF,
 *     for fine timestamps / busy delays. (Stock also runs TIM1/TIM3 at 100 kHz.)
 */
#ifndef TICK_H
#define TICK_H
#include <stdint.h>

#define TICK_HZ       100u        /* OS tick rate */
#define TICK_MS       10u         /* ms per OS tick */
#define US_PER_TICK   10u         /* 100 kHz counter resolution */

void     tick_init(void);
uint32_t tick_get(void);          /* 32-bit 100 Hz counter (10 ms units) */
uint32_t tick_micros(void);       /* TIM2 free-running µs (wraps ~655 ms) */
void     tick_delay_ms(uint32_t ms);

#endif /* TICK_H */