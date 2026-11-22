/* revert_stage.h — streaming hardware staging for the revert-from-custom aid (REPORT §5.15c).
 *
 * A stock SERVICE.UPG is ~595 KB — larger than the F4 RAM (192 KB + 64 KB CCM) — so the UPG cannot be
 * buffered in RAM. The CDC console STREAMS it: erase the update-pool range once, program pages as
 * bytes arrive, then read back the header to validate, write the xPAI descriptor LAST, and reset into
 * the boot which installs stock. The pure validation/build logic is in revert.c (host-tested).
 *
 * Brick-safe: the xPAI descriptor (the boot's update trigger) is committed only after the full UPG is
 * staged AND its header read-back-validated; the boot additionally checks the xPAI XOR + the UPG
 * XIE2/CRC before installing (§5.15c). A failed/partial upload leaves no valid command -> existing app
 * still launches.
 */
#ifndef REVERT_STAGE_H
#define REVERT_STAGE_H
#include <stdint.h>

/* Begin a revert upload of `filesize` bytes: bounds-check the xPAI length (filesize+2) and erase the
 * SPI update-pool range [0x110000, 0x110000+filesize). Returns 0 ready, -1 bad length / erase fail. */
int revert_stream_begin(uint32_t filesize);

/* Append `len` UPG bytes to the stream (sequential page program, no re-erase). Returns 0 ok, -1 if the
 * stream would overflow `filesize` or a program fails. Call repeatedly until `filesize` bytes sent. */
int revert_stream_write(const uint8_t *data, uint32_t len);

/* Finish: require exactly `filesize` bytes streamed, read back the 0x402-byte UPG header and validate
 * it (boot f+0x1eca mirror), build + write the xPAI descriptor @0x100000 LAST, read-back verify it.
 * Returns 0 committed (a reset will now install stock), -1 on any failure (nothing committed). */
int revert_stream_finish(void);

/* System reset into the boot (AIRCR SYSRESETREQ, boot f+0x18b6). Does not return. Call only after a
 * successful revert_stream_finish to trigger the stock install. */
void revert_trigger_reset(void);

#endif /* REVERT_STAGE_H */