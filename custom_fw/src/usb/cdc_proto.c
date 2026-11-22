/* cdc_proto.c — pure CDC revert-console framing parser (host-testable). See cdc_proto.h. */
#include "cdc_proto.h"

static int      mode_upload;
static uint32_t remaining;
static char     line[CDC_PROTO_LINE_MAX];
static uint32_t line_len;

void cdc_proto_init(void)
{
    mode_upload = 0;
    remaining   = 0;
    line_len    = 0;
}

int cdc_proto_in_upload(void)      { return mode_upload; }
uint32_t cdc_proto_remaining(void) { return mode_upload ? remaining : 0; }

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
    } else if (line_len > 7 &&
               line[0]=='R' && line[1]=='E' && line[2]=='V' && line[3]=='E' &&
               line[4]=='R' && line[5]=='T' && line[6]==' ') {
        uint32_t fs = 0;
        if (parse_u32(line + 7, &fs) == 0 && fs > 0) {
            r->event    = CDC_PROTO_REVERT;
            r->filesize = fs;
            mode_upload = 1;
            remaining   = fs;
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