/* revert_stage.h — hardware staging path for the revert-from-custom aid (REPORT §5.15c).
 *
 * Ties the host-tested revert core (revert.c) to the SPI-flash write path (spi4.c): validate the
 * uploaded stock UPG, stage it to the update pool, read-back verify, write the xPAI descriptor LAST
 * (so a failed/partial staging never leaves a valid update command), then reset into the boot which
 * installs stock. Hardware-only (register/SPI access); the pure validation/build logic is in revert.c
 * and host-unit-tested (test_revert.c).
 */
#ifndef REVERT_STAGE_H
#define REVERT_STAGE_H
#include <stdint.h>

/* Validate + stage a raw obfuscated stock UPG (`filesize` bytes) to the SPI update pool and write the
 * xPAI update descriptor. Returns 0 on success (a reset will now install stock), -1 on any validation
 * / write / read-back failure (nothing committed; the existing app still launches). Does NOT reset.
 * Brick-safe: the descriptor is written only after the full UPG is staged AND read-back verified. */
int revert_stage(const uint8_t *upg, uint32_t filesize);

/* System reset into the boot (AIRCR SYSRESETREQ, boot f+0x18b6). Does not return. Call only after a
 * successful revert_stage to trigger the stock install. */
void revert_trigger_reset(void);

#endif /* REVERT_STAGE_H */