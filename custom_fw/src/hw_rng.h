/* hw_rng.h — STM32F4 hardware RNG (0x50060800) driver + mbedTLS f_rng callback.
 * Recovered C013 RNG source (REPORT §5.9, Agent M): the stock mbedTLS is fed by the STM32
 * HW-RNG peripheral (RNG_CR/RNG_SR/RNG_DR), NOT ctr_drbg/entropy — so mbedtls_config.h sets
 * MBEDTLS_ECP_NO_INTERNAL_RNG and the glue wires this f_rng into mbedtls_ssl_conf_rng.
 * Communication/crypto only — drives NO power-stage GPIO. Register base is injectable for
 * host unit tests (hw_rng_set_regs); on target it is the peripheral 0x50060800. */
#ifndef HW_RNG_H
#define HW_RNG_H
#include <stdint.h>
#include <stddef.h>

#define HW_RNG_BASE   0x50060800u
#define HW_RNG_CR     0x00u   /* bit2 RNGEN (0x04), bit3 IE (0x08) */
#define HW_RNG_SR     0x04u   /* bit0 DRDY, bit1 CECS (clock error), bit2 SECS (seed error) */
#define HW_RNG_DR     0x08u   /* 32-bit random data (read clears DRDY) */
#define HW_RNG_CR_EN  0x04u
#define HW_RNG_SR_DRDY 0x01u

/* Enable the RNG peripheral clock (RCC AHB2ENR bit31) + RNGEN. Target only. */
void hw_rng_init(void);
/* Redirect the register window (host test injection); NULL restores the peripheral base. */
void hw_rng_set_regs(volatile uint32_t *regs);
/* Read one 32-bit random word (poll DRDY, bounded). Returns 0 ok, -1 timeout/clock-error. */
int hw_rng_read(uint32_t *out);
/* mbedTLS f_rng: fill out[0..len) from HW-RNG words. Signature matches mbedtls_ssl_conf_rng.
 * Returns 0 ok, -1 on RNG failure. ctx unused. */
int hw_rng_f_rng(void *ctx, unsigned char *out, size_t len);

#endif /* HW_RNG_H */
