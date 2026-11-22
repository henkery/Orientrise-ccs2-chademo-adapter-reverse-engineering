/* usb_cdc.c — USB CDC revert console (REPORT §5.15c). See usb_cdc.h for the protocol.
 *
 * Services the TinyUSB device CDC link: feeds RX bytes to the framing parser (cdc_proto), buffers
 * streamed UPG bytes into 256-byte pages and writes them to the SPI update pool (revert_stream_write),
 * and on the final byte validates + commits the xPAI descriptor (revert_stream_finish) then resets into
 * the boot. Command responses go back over CDC TX. The UPG is never buffered whole in RAM (~595 KB).
 */
#include "usb_cdc.h"
#include "cdc_proto.h"
#include "revert_stage.h"
#include "tusb.h"

static uint8_t  page[256];
static uint32_t page_fill;

static void cdc_send(const char *s)
{
    uint32_t len = 0;
    while (s[len])
        len++;
    uint32_t off = 0;
    while (off < len) {
        uint32_t n = tud_cdc_n_write(0, (const uint8_t *)s + off, len - off);
        tud_cdc_n_write_flush(0);
        off += n;
        if (n == 0)
            tud_task();                   /* TX fifo full: let the stack drain it */
    }
}

static void page_reset(void)
{
    page_fill = 0;
}

/* Flush the buffered upload page to the SPI pool. Returns 0 ok, -1 fail. */
static int page_flush(void)
{
    if (page_fill == 0)
        return 0;
    int rc = revert_stream_write(page, page_fill);
    page_fill = 0;
    return rc;
}

static void abort_upload(const char *msg)
{
    cdc_proto_init();                     /* leave UPLOAD mode, back to CMD */
    page_reset();
    cdc_send(msg);
}

void usb_cdc_init(void)
{
    cdc_proto_init();
    page_reset();
}

void usb_cdc_task(void)
{
    tud_task();                           /* TinyUSB device stack */

    if (!tud_cdc_n_connected(0))
        return;

    uint8_t rx[64];
    while (tud_cdc_n_available(0)) {
        uint32_t n = tud_cdc_n_read(0, rx, sizeof rx);
        if (n == 0)
            break;
        for (uint32_t i = 0; i < n; i++) {
            cdc_proto_result_t r;
            cdc_proto_feed(rx[i], &r);
            switch (r.event) {
            case CDC_PROTO_REVERT:
                page_reset();
                if (revert_stream_begin(r.filesize) == 0)
                    cdc_send("READY\r\n");
                else
                    abort_upload("ERR begin\r\n");
                break;

            case CDC_PROTO_UPLOAD_BYTE:
                page[page_fill++] = r.byte;
                if (page_fill == sizeof page) {
                    if (page_flush() != 0) {
                        abort_upload("ERR write\r\n");
                        break;
                    }
                }
                if (r.last) {
                    if (page_flush() != 0) {
                        abort_upload("ERR write\r\n");
                    } else if (revert_stream_finish() == 0) {
                        cdc_send("OK reverting\r\n");
                        revert_trigger_reset();   /* boot installs stock; does not return */
                    } else {
                        abort_upload("ERR stage\r\n");
                    }
                }
                break;

            case CDC_PROTO_PING:
                cdc_send("PONG\r\n");
                break;

            case CDC_PROTO_STATUS:
                cdc_send(cdc_proto_in_upload() ? "MODE UPLOAD\r\n" : "MODE CMD\r\n");
                break;

            case CDC_PROTO_HELP:
                cdc_send("CMDS: PING STATUS HELP ABORT REVERT <n>\r\n");
                break;

            case CDC_PROTO_ABORT:
                abort_upload("ABORTED\r\n");
                break;

            case CDC_PROTO_UNKNOWN:
                cdc_send("ERR unknown\r\n");
                break;

            case CDC_PROTO_LINE_OVERFLOW:
                cdc_send("ERR line too long\r\n");
                break;

            case CDC_PROTO_NONE:
            default:
                break;
            }
        }
    }
}