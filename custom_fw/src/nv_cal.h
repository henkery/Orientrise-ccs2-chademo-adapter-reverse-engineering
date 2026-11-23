/* nv_cal.h — factory HV two-point calibration read from external SPI flash (REPORT §5.21).
 * The stock app lazily reads a 0x44-byte cal record from SPI4 offset 0xFE000 into RAM
 * (getter 0x08052356 / lazy-init 0x0805231E) and validates magic + checksum. get_hv
 * (0x08052770) interpolates the live ADC raw between the two cal raw points. The custom
 * app reads the SAME stock record (external flash is untouched by app flashing).
 */
#ifndef NV_CAL_H
#define NV_CAL_H
#include <stdint.h>

typedef struct {
    int32_t raw_hi;   /* cal +0x0C: ADC raw at the high calibration voltage */
    int32_t raw_lo;   /* cal +0x10: ADC raw at the low calibration voltage  */
    int32_t eng_hi;   /* cal +0x14: engineering value (decivolts) at raw_hi */
    int32_t eng_lo;   /* cal +0x18: engineering value (decivolts) at raw_lo */
} hv_cal_t;

/* Read + validate the factory cal. Returns 0 on success, -1 if absent/invalid. */
int nv_cal_init(void);
/* Validated cal, or NULL if nv_cal_init() failed. */
const hv_cal_t *nv_cal_get(void);

/* Bench diagnostic (CALDUMP) — expose the raw record nv_cal_init() staged and recompute which
 * validation step it fails. Read-only; does not alter the stock replica or re-read the flash. */
const uint32_t *nv_cal_diag_words(void);  /* 17-word staging buffer (word[i] = SPI offset i*4) */
uint32_t nv_cal_diag_sum(void);           /* additive sum of words[0..15] (must equal word[16]) */
int nv_cal_diag_step(void);               /* 0 valid; 2 magic; 3 word14==0; 4 checksum; 5 divisor */

#endif /* NV_CAL_H */
