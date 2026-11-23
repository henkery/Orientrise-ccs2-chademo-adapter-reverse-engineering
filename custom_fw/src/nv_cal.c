/* nv_cal.c — factory HV two-point calibration read from external SPI flash (REPORT §5.21).
 *
 * Faithful replica of the stock cal lazy-init 0x0805231E + checksum 0x0805236A:
 *   - read 0x44 bytes (17 words) from SPI4 offset 0xFE000;
 *   - validate magic 0x41444A67 @ +0x3C (word 15), [+0x38] (word 14) != 0;
 *   - checksum = additive sum of the first 16 WORDS (0x40 bytes) == word @ +0x40 (word 16).
 *     (The checksum loop count 0x10 is a WORD count — `ldm r2!,{r3}` loads a word per step.)
 *   - get_hv fields: raw_hi=+0x0C, raw_lo=+0x10, eng_hi=+0x14, eng_lo=+0x18 (32-bit signed).
 * Read-only: the external NV record is never written. If the record is absent/invalid the
 * measurement reports 0 (and hv_init returns -1) rather than guessing a calibration.
 */
#include "nv_cal.h"
#include "spi4.h"

#define NV_CAL_ADDR   0xFE000u
#define NV_CAL_WORDS  17u                 /* 0x44 bytes */
#define NV_CAL_MAGIC  0x41444A67u

static uint32_t nv_words[NV_CAL_WORDS];   /* word-aligned staging buffer */
static hv_cal_t cal;
static int cal_valid;

int nv_cal_init(void)
{
    cal_valid = 0;
    if (spi4_read(NV_CAL_ADDR, (uint8_t *)nv_words, NV_CAL_WORDS * 4u) != 0)
        return -1;

    if (nv_words[15] != NV_CAL_MAGIC)     /* +0x3C */
        return -1;
    if (nv_words[14] == 0u)               /* +0x38 */
        return -1;

    uint32_t sum = 0;
    for (uint32_t i = 0; i < 16u; i++)    /* first 16 words = 0x40 bytes */
        sum += nv_words[i];
    if (sum != nv_words[16])              /* +0x40 */
        return -1;

    cal.raw_hi = (int32_t)nv_words[3];    /* +0x0C */
    cal.raw_lo = (int32_t)nv_words[4];    /* +0x10 */
    cal.eng_hi = (int32_t)nv_words[5];    /* +0x14 */
    cal.eng_lo = (int32_t)nv_words[6];    /* +0x18 */

    if (cal.raw_hi == cal.raw_lo)         /* guard the get_hv divisor */
        return -1;

    cal_valid = 1;
    return 0;
}

const hv_cal_t *nv_cal_get(void)
{
    return cal_valid ? &cal : (const hv_cal_t *)0;
}

/* ---- bench diagnostic (CALDUMP): expose the staged record + recompute the failing step.
 * Reads the same nv_words buffer nv_cal_init() filled; does not touch the stock replica. */
const uint32_t *nv_cal_diag_words(void)
{
    return nv_words;
}

uint32_t nv_cal_diag_sum(void)
{
    uint32_t sum = 0;
    for (uint32_t i = 0; i < 16u; i++)
        sum += nv_words[i];
    return sum;
}

int nv_cal_diag_step(void)
{
    if (nv_words[15] != NV_CAL_MAGIC)          return 2;   /* +0x3C magic */
    if (nv_words[14] == 0u)                    return 3;   /* +0x38 != 0 */
    if (nv_cal_diag_sum() != nv_words[16])     return 4;   /* +0x40 checksum */
    if (nv_words[3] == nv_words[4])            return 5;   /* raw_hi == raw_lo divisor guard */
    return 0;
}
