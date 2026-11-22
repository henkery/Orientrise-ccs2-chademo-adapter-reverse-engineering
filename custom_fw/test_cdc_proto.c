/* test_cdc_proto.c — host unit test for the CDC revert-console framing parser
 * (custom_fw/src/usb/cdc_proto.c).
 *
 * Build + run (host gcc; freestanding module, no library deps):
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -Isrc/usb -o test_cdc_proto \
 *       test_cdc_proto.c src/usb/cdc_proto.c && ./test_cdc_proto'
 *
 * Verifies: command parsing (PING/STATUS/HELP/ABORT/REVERT, case-insensitive), REVERT argument
 * validation (decimal, overflow, zero, junk), CMD->UPLOAD mode transition + exact byte counting with
 * the final-byte `last` flag, ABORT out of upload, CR/LF/CRLF line termination, empty lines, and
 * command-line overflow handling.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "cdc_proto.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

/* Feed a string then a terminating LF; return the result of the terminating byte (the command event).
 * Does NOT init — caller controls state. */
static cdc_proto_result_t feed_line(const char *s)
{
    cdc_proto_result_t r;
    for (; *s; s++)
        cdc_proto_feed((uint8_t)*s, &r);
    cdc_proto_feed((uint8_t)'\n', &r);
    return r;
}

int main(void)
{
    cdc_proto_result_t r;

    /* --- init state --- */
    cdc_proto_init();
    CHECK(cdc_proto_in_upload() == 0, "init: not in upload");
    CHECK(cdc_proto_remaining() == 0, "init: remaining 0");

    /* --- simple commands --- */
    cdc_proto_init();
    r = feed_line("PING");
    CHECK(r.event == CDC_PROTO_PING, "PING -> PING event");
    r = feed_line("STATUS");
    CHECK(r.event == CDC_PROTO_STATUS, "STATUS -> STATUS event");
    r = feed_line("HELP");
    CHECK(r.event == CDC_PROTO_HELP, "HELP -> HELP event");
    r = feed_line("ABORT");
    CHECK(r.event == CDC_PROTO_ABORT, "ABORT -> ABORT event");
    CHECK(cdc_proto_in_upload() == 0, "ABORT in CMD stays CMD");

    /* --- case-insensitive --- */
    cdc_proto_init();
    r = feed_line("ping");
    CHECK(r.event == CDC_PROTO_PING, "lowercase ping -> PING");
    r = feed_line("Revert 50");
    CHECK(r.event == CDC_PROTO_REVERT && r.filesize == 50, "mixed-case Revert 50 -> REVERT 50");

    /* --- unknown / malformed --- */
    cdc_proto_init();
    r = feed_line("BOGUS");
    CHECK(r.event == CDC_PROTO_UNKNOWN, "unknown command -> UNKNOWN");
    r = feed_line("");
    CHECK(r.event == CDC_PROTO_NONE, "empty line -> NONE");
    r = feed_line("REVERT");
    CHECK(r.event == CDC_PROTO_UNKNOWN, "REVERT no arg -> UNKNOWN");
    r = feed_line("REVERT ");
    CHECK(r.event == CDC_PROTO_UNKNOWN, "REVERT space-only -> UNKNOWN");
    r = feed_line("REVERT 0");
    CHECK(r.event == CDC_PROTO_UNKNOWN, "REVERT 0 -> UNKNOWN");
    CHECK(cdc_proto_in_upload() == 0, "REVERT 0 stays CMD");
    r = feed_line("REVERT abc");
    CHECK(r.event == CDC_PROTO_UNKNOWN, "REVERT non-numeric -> UNKNOWN");
    r = feed_line("REVERT 100x");
    CHECK(r.event == CDC_PROTO_UNKNOWN, "REVERT trailing junk -> UNKNOWN");
    r = feed_line("REVERT 4294967296");
    CHECK(r.event == CDC_PROTO_UNKNOWN, "REVERT u32 overflow -> UNKNOWN");
    r = feed_line("REVERT 4294967295");
    CHECK(r.event == CDC_PROTO_REVERT && r.filesize == 0xFFFFFFFFu, "REVERT u32 max accepted");

    /* --- REVERT -> UPLOAD mode + byte counting --- */
    cdc_proto_init();
    r = feed_line("REVERT 100");
    CHECK(r.event == CDC_PROTO_REVERT && r.filesize == 100, "REVERT 100 -> REVERT 100");
    CHECK(cdc_proto_in_upload() == 1, "REVERT enters UPLOAD");
    CHECK(cdc_proto_remaining() == 100, "remaining 100 after REVERT");
    {
        int last_seen = 0;
        uint32_t count = 0;
        for (uint32_t i = 0; i < 100; i++) {
            cdc_proto_feed((uint8_t)(i & 0xFFu), &r);
            CHECK(r.event == CDC_PROTO_UPLOAD_BYTE, "upload byte event");
            CHECK(r.byte == (uint8_t)(i & 0xFFu), "upload byte value passthrough");
            if (r.last) { last_seen = 1; count = i + 1; }
        }
        CHECK(last_seen == 1, "final upload byte flagged last");
        CHECK(count == 100, "last flag on exactly the 100th byte");
        CHECK(cdc_proto_in_upload() == 0, "returns to CMD after final byte");
        CHECK(cdc_proto_remaining() == 0, "remaining 0 after upload complete");
    }
    /* after upload, commands work again */
    r = feed_line("PING");
    CHECK(r.event == CDC_PROTO_PING, "PING works after upload completes");

    /* --- single-byte upload (REVERT 1) --- */
    cdc_proto_init();
    r = feed_line("REVERT 1");
    CHECK(r.event == CDC_PROTO_REVERT && r.filesize == 1, "REVERT 1 accepted");
    cdc_proto_feed(0xABu, &r);
    CHECK(r.event == CDC_PROTO_UPLOAD_BYTE && r.byte == 0xABu && r.last == 1, "REVERT 1 single byte last");
    CHECK(cdc_proto_in_upload() == 0, "REVERT 1 returns to CMD");

    /* --- ABORT during upload --- */
    cdc_proto_init();
    feed_line("REVERT 1000");
    CHECK(cdc_proto_in_upload() == 1, "upload active before ABORT");
    /* In UPLOAD mode bytes are data, so ABORT must be issued by the glue resetting the parser;
     * verify the glue-level abort path via cdc_proto_init (the glue calls init on ABORT command). */
    cdc_proto_init();
    CHECK(cdc_proto_in_upload() == 0, "init aborts upload (glue ABORT path)");

    /* --- CR / LF / CRLF termination --- */
    cdc_proto_init();
    for (const char *s = "PING"; *s; s++) cdc_proto_feed((uint8_t)*s, &r);
    cdc_proto_feed((uint8_t)'\r', &r);
    CHECK(r.event == CDC_PROTO_PING, "CR terminates line");
    cdc_proto_feed((uint8_t)'\n', &r);
    CHECK(r.event == CDC_PROTO_NONE, "LF after CR -> empty line NONE (CRLF = one command)");

    /* --- partial line across feeds --- */
    cdc_proto_init();
    cdc_proto_feed('P', &r);
    CHECK(r.event == CDC_PROTO_NONE, "partial line P -> NONE");
    cdc_proto_feed('I', &r);
    cdc_proto_feed('N', &r);
    cdc_proto_feed('G', &r);
    CHECK(r.event == CDC_PROTO_NONE, "partial line PING (no term) -> NONE");
    cdc_proto_feed('\n', &r);
    CHECK(r.event == CDC_PROTO_PING, "completed partial line -> PING");

    /* --- line overflow --- */
    cdc_proto_init();
    {
        int overflow = 0;
        for (uint32_t i = 0; i < CDC_PROTO_LINE_MAX + 10u; i++) {
            cdc_proto_feed('A', &r);
            if (r.event == CDC_PROTO_LINE_OVERFLOW) overflow = 1;
        }
        CHECK(overflow == 1, "overlong line -> LINE_OVERFLOW");
        cdc_proto_feed('\n', &r);
        CHECK(r.event == CDC_PROTO_UNKNOWN || r.event == CDC_PROTO_NONE, "overlong line reset on term");
        r = feed_line("PING");
        CHECK(r.event == CDC_PROTO_PING, "parser recovers after overflow");
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}