/* cdc_proto.h — pure CDC revert-console framing parser (host-testable).
 *
 * Byte-fed state machine with two modes:
 *   CMD    — accumulate a CR/LF-terminated line, then parse a command:
 *              REVERT <n>  -> begin a raw UPG upload of <n> bytes (enter UPLOAD mode)
 *              PING / STATUS / HELP / ABORT
 *   UPLOAD — pass through exactly <n> raw bytes (the obfuscated UPG); the final byte is flagged
 *            `last` and the parser returns to CMD mode.
 *
 * The parser emits events; the hardware glue (usb_cdc.c) acts on them (revert_stream_begin/write/
 * finish + reset, CDC TX responses). No hardware deps here — host-unit-tested (test_cdc_proto.c).
 * The REVERT argument is the UPG FILE SIZE in bytes (decimal); the xPAI length convention (filesize+2)
 * is applied by the staging core, not here.
 */
#ifndef CDC_PROTO_H
#define CDC_PROTO_H
#include <stdint.h>

#define CDC_PROTO_LINE_MAX 64u

typedef enum {
    CDC_PROTO_NONE = 0,      /* byte consumed, no event (mid-line / empty line)        */
    CDC_PROTO_REVERT,        /* "REVERT <n>": filesize set, entered UPLOAD mode        */
    CDC_PROTO_PING,          /* "PING"                                                 */
    CDC_PROTO_STATUS,        /* "STATUS"                                               */
    CDC_PROTO_HELP,          /* "HELP"                                                 */
    CDC_PROTO_ABORT,         /* "ABORT": left UPLOAD mode (or no-op in CMD)            */
    CDC_PROTO_UNKNOWN,       /* unrecognized / malformed line                          */
    CDC_PROTO_UPLOAD_BYTE,   /* upload data byte: byte set, last=1 on the final byte   */
    CDC_PROTO_LINE_OVERFLOW  /* command line exceeded CDC_PROTO_LINE_MAX (line reset)  */
} cdc_proto_event_t;

typedef struct {
    cdc_proto_event_t event;
    uint32_t filesize;       /* CDC_PROTO_REVERT: upload byte count                    */
    uint8_t  byte;           /* CDC_PROTO_UPLOAD_BYTE: the raw UPG byte                */
    int      last;           /* CDC_PROTO_UPLOAD_BYTE: 1 if this is the final byte     */
} cdc_proto_result_t;

void cdc_proto_init(void);
/* Feed one received byte; fills *r with the resulting event (CDC_PROTO_NONE if no event). */
void cdc_proto_feed(uint8_t b, cdc_proto_result_t *r);
int cdc_proto_in_upload(void);          /* 1 while in UPLOAD mode */
uint32_t cdc_proto_remaining(void);     /* upload bytes still expected (0 in CMD mode) */

#endif /* CDC_PROTO_H */