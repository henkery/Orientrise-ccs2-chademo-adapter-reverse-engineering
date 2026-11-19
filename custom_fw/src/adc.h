/* adc.h — HV measurement ADC front-end (REPORT §5.21 measurement addendum).
 * ADC1 (PB0, ch8) + ADC2 (PB1, ch9) regular-simultaneous, TIM8-triggered, DMA2 circular,
 * with the stock differential-accumulation DSP that produces the live HV raw used by get_hv.
 */
#ifndef ADC_H
#define ADC_H
#include <stdint.h>

void adc_init(void);
/* Live HV raw = accumulated sum(ADC1 - ADC2) over 25000 differential samples (~200 ms).
 * This is the exact scale of the factory cal raw_lo/raw_hi (get_hv interpolates it). */
int32_t adc_get_live_raw(void);

#endif /* ADC_H */
