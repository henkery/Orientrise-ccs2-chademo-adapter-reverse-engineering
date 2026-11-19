/* hv.c — HV measurement result (REPORT §5.21). Faithful replica of get_hv 0x08052770:
 *   get_hv = eng_lo + (live_raw - raw_lo) * (eng_hi - eng_lo) / (raw_hi - raw_lo)
 * (signed 64-bit product / 32-bit divisor, matching the stock smull + __aeabi_ldivmod),
 * then outvol = get_hv()/10 (volts). The live_raw comes from the stock-scale differential
 * ADC accumulation (adc.c); the two cal points come from the factory SPI-flash record
 * (nv_cal.c). Measurement only — no power-stage drive.
 */
#include "hv.h"
#include "nv_cal.h"
#include "adc.h"
#include "spi4.h"

static int cal_ok;

int hv_init(void)
{
    spi4_init();
    cal_ok = (nv_cal_init() == 0);
    adc_init();                 /* front-end runs regardless; cal only scales the result */
    return cal_ok ? 0 : -1;
}

int hv_cal_valid(void)
{
    return cal_ok;
}

int32_t hv_get_raw(void)
{
    const hv_cal_t *c = nv_cal_get();
    if (!c)
        return 0;

    int32_t dr = c->raw_hi - c->raw_lo;
    if (dr == 0)
        return 0;

    int32_t live = adc_get_live_raw();
    int64_t num = (int64_t)(live - c->raw_lo) * (int64_t)(c->eng_hi - c->eng_lo);
    int32_t q = (int32_t)(num / dr);
    return q + c->eng_lo;
}

int32_t hv_get_outvol(void)
{
    return hv_get_raw() / 10;
}
