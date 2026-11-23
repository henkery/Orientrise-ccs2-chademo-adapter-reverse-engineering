/* cdc_proto.h — pure CDC revert-console + bench framing parser (host-testable).
 *
 * Byte-fed state machine with two modes:
 *   CMD    — accumulate a CR/LF-terminated line, then parse a command:
 *              REVERT <n>  -> begin a raw UPG upload of <n> bytes (enter UPLOAD mode, sink REVERT)
 *              INJE <n>    -> begin a raw Ethernet-frame upload of <n> bytes (UPLOAD mode, sink ETH)
 *              INJC <id> <dlc> <b0..bN> -> inject a CAN frame (all hex; exactly dlc data bytes)
 *              MEAS / CAN / NET / STM  -> read-only measurement readback (Stage-1 bench)
 *              PING / STATUS / HELP / ABORT
 *   UPLOAD — pass through exactly <n> raw bytes; the final byte is flagged `last` and the parser
 *            returns to CMD mode. The upload SINK (REVERT vs ETH) selects where the glue routes the
 *            bytes: revert_stream_write (SPI staging) or v2g_net_rx_ethernet (RX injection).
 *
 * The parser emits events; the hardware glue (usb_cdc.c) acts on them (revert_stream_begin/write/
 * finish + reset, CAN/Ethernet injection, measurement readback, CDC TX responses). No hardware deps
 * here — host-unit-tested (test_cdc_proto.c). The REVERT/INJE argument is a byte count (decimal); the
 * xPAI length convention (filesize+2) is applied by the staging core, not here.
 */
#ifndef CDC_PROTO_H
#define CDC_PROTO_H
#include <stdint.h>

#define CDC_PROTO_LINE_MAX 64u

typedef enum {
    CDC_PROTO_NONE = 0,      /* byte consumed, no event (mid-line / empty line)        */
    CDC_PROTO_REVERT,        /* "REVERT <n>": filesize set, entered UPLOAD (sink REVERT)*/
    CDC_PROTO_PING,          /* "PING"                                                 */
    CDC_PROTO_STATUS,        /* "STATUS"                                               */
    CDC_PROTO_HELP,          /* "HELP"                                                 */
    CDC_PROTO_ABORT,         /* "ABORT": left UPLOAD mode (or no-op in CMD)            */
    CDC_PROTO_UNKNOWN,       /* unrecognized / malformed line                          */
    CDC_PROTO_UPLOAD_BYTE,   /* upload data byte: byte set, last=1 on the final byte   */
    CDC_PROTO_LINE_OVERFLOW, /* command line exceeded CDC_PROTO_LINE_MAX (line reset)  */
    CDC_PROTO_MEAS,          /* "MEAS": HV + CP/PP measurement readback                */
    CDC_PROTO_CAN,           /* "CAN": CHAdeMO H100/H101/H102 field readback           */
    CDC_PROTO_NET,           /* "NET": v2g_net transport state readback                */
    CDC_PROTO_STM,           /* "STM": charge-stm shadow state readback                */
    CDC_PROTO_INJC,          /* "INJC <id> <dlc> <bytes>": CAN frame inject (inj_* set)*/
    CDC_PROTO_INJE,          /* "INJE <n>": filesize set, entered UPLOAD (sink ETH)    */
    CDC_PROTO_CALDUMP,       /* "CALDUMP": raw HV cal record + validation + live raw   */
    CDC_PROTO_CALSCAN,       /* "CALSCAN": scan ext-flash for cal magic + region fill  */
    CDC_PROTO_CALFIND        /* "CALFIND": map ext factory data + scan int-flash magic */
} cdc_proto_event_t;

/* Upload sink: where the glue routes UPLOAD_BYTE data. REVERT = SPI staging; ETH = RX injection. */
typedef enum {
    CDC_SINK_REVERT = 0,
    CDC_SINK_ETH    = 1
} cdc_sink_t;

typedef struct {
    cdc_proto_event_t event;
    uint32_t filesize;       /* CDC_PROTO_REVERT/INJE: upload byte count               */
    uint8_t  byte;           /* CDC_PROTO_UPLOAD_BYTE: the raw data byte               */
    int      last;           /* CDC_PROTO_UPLOAD_BYTE: 1 if this is the final byte     */
    uint32_t inj_id;         /* CDC_PROTO_INJC: CAN standard ID (hex)                  */
    uint8_t  inj_dlc;        /* CDC_PROTO_INJC: data length 0..8                       */
    uint8_t  inj_data[8];    /* CDC_PROTO_INJC: data bytes (hex)                       */
} cdc_proto_result_t;

void cdc_proto_init(void);
/* Feed one received byte; fills *r with the resulting event (CDC_PROTO_NONE if no event). */
void cdc_proto_feed(uint8_t b, cdc_proto_result_t *r);
int cdc_proto_in_upload(void);          /* 1 while in UPLOAD mode */
uint32_t cdc_proto_remaining(void);     /* upload bytes still expected (0 in CMD mode) */
cdc_sink_t cdc_proto_upload_sink(void); /* active upload sink (REVERT default; valid in UPLOAD) */

#endif /* CDC_PROTO_H */