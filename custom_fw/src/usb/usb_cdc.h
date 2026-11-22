/* usb_cdc.h — USB CDC revert console (REPORT §5.15c). Drives the framing parser (cdc_proto) + the
 * streaming staging core (revert_stage) over a TinyUSB device CDC link.
 *
 * Protocol (host -> device, lines terminated CR/LF; then raw bytes for an upload):
 *   PING            -> "PONG"
 *   HELP            -> command summary
 *   STATUS          -> "MODE CMD" / "MODE UPLOAD"
 *   REVERT <n>      -> "READY"; then the host streams exactly <n> raw SERVICE.UPG bytes; on the last
 *                      byte the device validates + commits the xPAI descriptor -> "OK reverting" +
 *                      reset into the boot (installs stock). Failure -> "ERR ..." and back to CMD.
 *   ABORT           -> abort an in-progress upload (the glue resets the parser), "ABORTED"
 *
 * The UPG is streamed straight to SPI flash (it is ~595 KB, larger than RAM). Brick-safe: the xPAI
 * descriptor is committed only after the full UPG is staged + header-validated (revert_stage).
 */
#ifndef USB_CDC_H
#define USB_CDC_H

/* Reset the console framing state. Call once after usb_hw_init. */
void usb_cdc_init(void);

/* Poll the TinyUSB device stack + service the CDC console. Call every main-loop iteration. */
void usb_cdc_task(void);

#endif /* USB_CDC_H */