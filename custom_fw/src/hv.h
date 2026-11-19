/* hv.h — HV measurement result (REPORT §5.21). get_hv two-point interpolation of the live
 * ADC raw against the factory cal, then outvol = get_hv()/10 (volts). Measurement only.
 */
#ifndef HV_H
#define HV_H
#include <stdint.h>

/* Init SPI4 + read factory cal + start the ADC front-end. Returns 0 if a valid factory cal
 * was read (measurement meaningful), -1 if absent/invalid (measurement reports 0). The ADC
 * runs either way; only the engineering-unit conversion needs the cal. */
int hv_init(void);
int hv_cal_valid(void);
/* get_hv(): engineering value in decivolts (0.1 V), 0 if no valid cal. */
int32_t hv_get_raw(void);
/* outvol = get_hv()/10, in volts. */
int32_t hv_get_outvol(void);

#endif /* HV_H */
