/* spi4.h — SPI4 external-flash read transport (REPORT §5.21 measurement addendum).
 * The factory HV calibration lives in an external 2 MB SPI flash on SPI4 (CS = PE11,
 * active-low), NOT in STM32 internal flash. App flashing only writes internal sectors 5-9,
 * so this external NV region is preserved and the custom app can read the stock cal directly.
 * Byte-derived from the stock NV read core 0x08088CFE (READ 0x03) + SPI4 init 0x08088C38.
 */
#ifndef SPI4_H
#define SPI4_H
#include <stdint.h>

void spi4_init(void);
/* READ (0x03) `len` bytes from 24-bit flash offset `addr` into `dst`.
 * Returns 0 on success, -1 if [addr, addr+len) falls outside the 2 MB space. */
int spi4_read(uint32_t addr, uint8_t *dst, uint32_t len);

#endif /* SPI4_H */
