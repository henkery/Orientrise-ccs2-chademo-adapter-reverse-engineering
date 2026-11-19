/* gpio.h — power-stage GPIO map + safe-state init (REPORT §5.5c / §5.17, analyze78/81).
 *
 * Pin map is hardware-invariant (C009 == C013 board). Active levels below were byte-derived
 * from the C013 drive primitives' BSRR set/reset logic (BSRR low16 = SET->HIGH, high16 =
 * RESET->LOW); see REPORT §5.5c. "SAFE" = the de-asserted level that keeps every contactor
 * OPEN and the charge path OFF — no HV can appear.
 *
 *   signal                 pin(s)      active   SAFE
 *   CHAdeMO enable d1      PE7         HIGH     LOW
 *   CHAdeMO enable d2      PE8         HIGH     LOW
 *   BatteryPower (inner)   PD8         HIGH     LOW   (contactor open)
 *   PreChargeRELAY         PB10+PB11   HIGH     LOW   (relay open)
 *   BatteryCharge          PC9         LOW      HIGH  (charge off)
 *   e-lock motor           PD3+PE4     LOW      HIGH  (motor off)
 *
 * SAFETY: gpio_safe_init() only drives DE-ASSERTED levels (it is not power-stage drive).
 * The asserted drive functions are added later, GATED behind a compile-time safety flag,
 * and stay disabled until bench-validated. Feedback inputs (PE10/PD9/PD10/PC8/PB12/PB8)
 * are left as reset-state inputs here and configured in the measurement layer.
 */
#ifndef GPIO_H
#define GPIO_H
#include <stdint.h>

/* Drive all power-stage outputs to their SAFE (de-asserted) state, glitch-free.
 * Call once after rcc_init(), before interrupts are enabled. */
void gpio_safe_init(void);

#endif /* GPIO_H */
