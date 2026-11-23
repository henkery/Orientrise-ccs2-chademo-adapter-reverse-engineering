/* cdc_proto.c — pure CDC revert-console framing parser (host-testable). See cdc_proto.h. */
#include "cdc_proto.h"

static int        mode_upload;
static uint32_t   remaining;
static cdc_sink_t upload_sink;
static char       line[CDC_PROTO_LINE_MAX];
static uint32_t   line_len;

void cdc_proto_init(void)
{
    mode_upload = 0;
    remaining   = 0;
    upload_sink = CDC_SINK_REVERT;
    line_len    = 0;
}

int cdc_proto_in_upload(void)      { return mode_upload; }
uint32_t cdc_proto_remaining(void) { return mode_upload ? remaining : 0; }
cdc_sink_t cdc_proto_upload_sink(void) { return upload_sink; }

/* Parse a pure unsigned decimal string (no sign/space/junk) into *out. Returns 0 ok, -1 malformed. */
static int parse_u32(const char *s, uint32_t *out)
{
    if (!*s)
        return -1;
    uint32_t v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return -1;
        uint32_t d = (uint32_t)(*s - '0');
        if (v > (0xFFFFFFFFu - d) / 10u)   /* overflow */
            return -1;
        v = v * 10u + d;
    }
    *out = v;
    return 0;
}

/* Parse one hex token at *p (skips leading spaces). Advances *p to the token end (before the next
 * space). The line is already uppercased, so digits are 0-9/A-F. Returns 0 ok (*out set), -1 if no
 * hex digit, overflow, or the token is not space/end-delimited. */
static int parse_hex_tok(const char **p, uint32_t *out)
{
    const char *s = *p;
    while (*s == ' ')
        s++;
    uint32_t v = 0;
    int nd = 0;
    for (; *s; s++) {
        char c = *s;
        uint32_t d;
        if (c >= '0' && c <= '9')      d = (uint32_t)(c - '0');
        else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
        else break;
        if (v > (0xFFFFFFFFu - d) / 16u)   /* overflow */
            return -1;
        v = v * 16u + d;
        nd++;
    }
    if (nd == 0 || (*s && *s != ' '))
        return -1;
    *out = v;
    *p = s;
    return 0;
}

static int streq(const char *a, const char *b)
{
    while (*a && *b) {
        if (*a != *b)
            return 0;
        a++; b++;
    }
    return *a == *b;
}

/* Parse a completed (CR/LF-stripped, uppercased) command line. Emits the event; enters UPLOAD mode
 * for a valid REVERT. */
static void parse_line(cdc_proto_result_t *r)
{
    if (line_len == 0) {
        r->event = CDC_PROTO_NONE;
        return;
    }
    line[line_len] = '\0';
    for (uint32_t i = 0; i < line_len; i++)
        if (line[i] >= 'a' && line[i] <= 'z')
            line[i] = (char)(line[i] - 'a' + 'A');

    if (streq(line, "PING")) {
        r->event = CDC_PROTO_PING;
    } else if (streq(line, "STATUS")) {
        r->event = CDC_PROTO_STATUS;
    } else if (streq(line, "HELP")) {
        r->event = CDC_PROTO_HELP;
    } else if (streq(line, "ABORT")) {
        r->event = CDC_PROTO_ABORT;
    } else if (streq(line, "MEAS")) {
        r->event = CDC_PROTO_MEAS;
    } else if (streq(line, "CAN")) {
        r->event = CDC_PROTO_CAN;
    } else if (streq(line, "NET")) {
        r->event = CDC_PROTO_NET;
    } else if (streq(line, "STM")) {
        r->event = CDC_PROTO_STM;
    } else if (streq(line, "CALDUMP")) {
        r->event = CDC_PROTO_CALDUMP;
    } else if (streq(line, "CALSCAN")) {
        r->event = CDC_PROTO_CALSCAN;
    } else if (streq(line, "CALFIND")) {
        r->event = CDC_PROTO_CALFIND;
    } else if (line_len > 7 &&
               line[0]=='R' && line[1]=='E' && line[2]=='V' && line[3]=='E' &&
               line[4]=='R' && line[5]=='T' && line[6]==' ') {
        uint32_t fs = 0;
        if (parse_u32(line + 7, &fs) == 0 && fs > 0) {
            r->event    = CDC_PROTO_REVERT;
            r->filesize = fs;
            mode_upload = 1;
            remaining   = fs;
            upload_sink = CDC_SINK_REVERT;
        } else {
            r->event = CDC_PROTO_UNKNOWN;
        }
    } else if (line_len > 5 &&
               line[0]=='I' && line[1]=='N' && line[2]=='J' && line[3]=='E' &&
               line[4]==' ') {
        uint32_t fs = 0;
        if (parse_u32(line + 5, &fs) == 0 && fs > 0) {
            r->event    = CDC_PROTO_INJE;
            r->filesize = fs;
            mode_upload = 1;
            remaining   = fs;
            upload_sink = CDC_SINK_ETH;
        } else {
            r->event = CDC_PROTO_UNKNOWN;
        }
    } else if (line_len > 5 &&
               line[0]=='I' && line[1]=='N' && line[2]=='J' && line[3]=='C' &&
               line[4]==' ') {
        /* INJC <id> <dlc> <b0..bN> — all hex; exactly dlc (0..8) data bytes, no trailing junk. */
        const char *p = line + 5;
        uint32_t id = 0, dlc = 0;
        int ok = (parse_hex_tok(&p, &id) == 0) && (id <= 0x7FFu) &&
                 (parse_hex_tok(&p, &dlc) == 0) && (dlc <= 8u);
        for (uint32_t i = 0; ok && i < dlc; i++) {
            uint32_t b = 0;
            if (parse_hex_tok(&p, &b) != 0 || b > 0xFFu)
                ok = 0;
            else
                r->inj_data[i] = (uint8_t)b;
        }
        if (ok) {
            while (*p == ' ')
                p++;
            if (*p != '\0')
                ok = 0;
        }
        if (ok) {
            r->event   = CDC_PROTO_INJC;
            r->inj_id  = id;
            r->inj_dlc = (uint8_t)dlc;
        } else {
            r->event = CDC_PROTO_UNKNOWN;
        }
    } else {
        r->event = CDC_PROTO_UNKNOWN;
    }
}

void cdc_proto_feed(uint8_t b, cdc_proto_result_t *r)
{
    r->event    = CDC_PROTO_NONE;
    r->filesize = 0;
    r->byte     = 0;
    r->last     = 0;
    r->inj_id   = 0;
    r->inj_dlc  = 0;
    for (uint32_t i = 0; i < 8u; i++)
        r->inj_data[i] = 0;

    if (mode_upload) {
        r->event = CDC_PROTO_UPLOAD_BYTE;
        r->byte  = b;
        remaining--;
        if (remaining == 0) {
            r->last     = 1;
            mode_upload = 0;
        }
        return;
    }

    if (b == '\n' || b == '\r') {
        parse_line(r);
        line_len = 0;
        return;
    }

    if (line_len >= CDC_PROTO_LINE_MAX - 1u) {
        r->event = CDC_PROTO_LINE_OVERFLOW;
        line_len = 0;
        return;
    }
    line[line_len++] = (char)b;
}