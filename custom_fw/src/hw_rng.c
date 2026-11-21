/* hw_rng.c — STM32F4 HW-RNG driver + mbedTLS f_rng (see hw_rng.h). Recovered C013 RNG source.
 * Communication/crypto only — NO power-stage GPIO. Bounded DRDY poll (no infinite block). */
#include "hw_rng.h"

static volatile uint32_t *rng = (volatile uint32_t *)HW_RNG_BASE;

void hw_rng_set_regs(volatile uint32_t *regs)
{
    rng = regs ? regs : (volatile uint32_t *)HW_RNG_BASE;
}

void hw_rng_init(void)
{
    /* RCC AHB2ENR (0x40023830) bit31 = RNGEN; then RNG_CR RNGEN. Target peripheral access. */
    volatile uint32_t *ahb2enr = (volatile uint32_t *)0x40023830u;
    *ahb2enr |= (1u << 31);
    (void)*ahb2enr;                       /* short delay after clock enable */
    rng[HW_RNG_CR / 4u] |= HW_RNG_CR_EN;
}

int hw_rng_read(uint32_t *out)
{
    /* Poll DRDY (bounded ~100000 iterations); recover from clock/seed error by re-enabling. */
    for (uint32_t i = 0; i < 100000u; i++) {
        uint32_t sr = rng[HW_RNG_SR / 4u];
        if (sr & HW_RNG_SR_DRDY) {
            *out = rng[HW_RNG_DR / 4u];
            return 0;
        }
        if (sr & 0x06u) {                 /* CECS/SECS: clear + re-enable */
            rng[HW_RNG_SR / 4u] = 0;
            rng[HW_RNG_CR / 4u] |= HW_RNG_CR_EN;
        }
    }
    return -1;
}

int hw_rng_f_rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    size_t i = 0;
    while (i < len) {
        uint32_t w;
        if (hw_rng_read(&w) != 0) return -1;
        for (unsigned b = 0; b < 4u && i < len; b++, i++)
            out[i] = (unsigned char)(w >> (8u * b));   /* little-endian word bytes */
    }
    return 0;
}
