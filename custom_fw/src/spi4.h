/* spi4.h — SPI4 external-flash transport (REPORT §5.21 measurement addendum + §5.15c revert).
 * The factory HV calibration lives in an external 2 MB SPI flash on SPI4 (CS = PE11,
 * active-low), NOT in STM32 internal flash. App flashing only writes internal sectors 5-9,
 * so this external NV region is preserved and the custom app can read the stock cal directly.
 * Byte-derived from the stock NV read core 0x08088CFE (READ 0x03) + SPI4 init 0x08088C38.
 *
 * The write path (spi4_write) mirrors the boot update-pool writer f+0x1b42 (WREN/PP/SE/RDSR,
 * f+0x1bb2/f+0x1c3e/f+0x1ca4/f+0x1aa4) and is restricted to the UPPER-1 MB update pool
 * [0x100000,0x200000) — the lower 1 MB (factory NV cal) is never erased/programmed. Used by the
 * revert-from-custom channel (revert.c) to stage a stock SERVICE.UPG + the xPAI descriptor.
 */
#ifndef SPI4_H
#define SPI4_H
#include <stdint.h>

void spi4_init(void);
/* READ (0x03) `len` bytes from 24-bit flash offset `addr` into `dst`.
 * Returns 0 on success, -1 if [addr, addr+len) falls outside the 2 MB space. */
int spi4_read(uint32_t addr, uint8_t *dst, uint32_t len);

/* High-level page/sector-aware write (boot f+0x1b42) of `len` bytes from `src` to 24-bit flash
 * offset `addr`. Erases 4 KB sectors as needed (first sector only if sector-aligned) and programs
 * 256-byte pages, feeding the IWDG after each erase. Restricted to the update pool
 * [0x100000,0x200000); returns 0 on success, -1 if the range is outside the pool or a program/erase
 * fails. `addr`/`len` need not be page/sector aligned (the chunking handles partial pages/sectors). */
int spi4_write(uint32_t addr, const uint8_t *src, uint32_t len);

#endif /* SPI4_H */
