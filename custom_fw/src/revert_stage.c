/* revert_stage.c — streaming hardware staging for the revert-from-custom aid (REPORT §5.15c).
 *
 * A ~595 KB stock UPG cannot fit in F4 RAM, so it is streamed from the CDC console straight to the
 * SPI update pool:
 *   begin  — bounds-check xPAI len (filesize+2), erase [0x110000, 0x110000+filesize) ONCE.
 *   write  — program pages sequentially as bytes arrive (no re-erase).
 *   finish — read back the 0x402-byte header, revert_upg_check (boot f+0x1eca mirror), build + write
 *            the xPAI descriptor @0x100000 LAST, read-back verify it.
 *   reset  — AIRCR SYSRESETREQ (f+0x18b6); the boot validates + installs stock verbatim (§5.16).
 *
 * The descriptor is committed only after the full UPG is staged AND its header validated, so a
 * failed/partial upload never leaves a valid update command (no brick). The boot additionally checks
 * the xPAI XOR + the UPG XIE2/CRC (incl. the whole-image trailer CRC) before installing.
 */
#include "revert_stage.h"
#include "revert.h"
#include "spi4.h"

#define AIRCR (*(volatile uint32_t *)0xE000ED0Cu)

static uint32_t stream_filesize;
static uint32_t stream_offset;

int revert_stream_begin(uint32_t filesize)
{
    uint32_t len = revert_xpai_len_for(filesize);
    if (len < REVERT_LEN_MIN || len > REVERT_LEN_MAX)
        return -1;
    if (spi4_erase_range(REVERT_UPG_PHYS, filesize) != 0)
        return -1;
    stream_filesize = filesize;
    stream_offset   = 0;
    return 0;
}

int revert_stream_write(const uint8_t *data, uint32_t len)
{
    if (!data || stream_offset + len > stream_filesize)
        return -1;
    if (len == 0)
        return 0;
    if (spi4_program(REVERT_UPG_PHYS + stream_offset, data, len) != 0)
        return -1;
    stream_offset += len;
    return 0;
}

int revert_stream_finish(void)
{
    if (stream_offset != stream_filesize)
        return -1;

    /* Read back the staged header (key-echo + 0x400 obfuscated header) and validate it exactly as the
     * boot f+0x1eca does. The body is guarded by the boot's whole-image trailer CRC at install time. */
    uint8_t hdr[REVERT_UPG_HDR];
    if (spi4_read(REVERT_UPG_PHYS, hdr, sizeof hdr) != 0)
        return -1;
    uint32_t len = revert_xpai_len_for(stream_filesize);
    if (revert_upg_check(hdr, len) != 0)
        return -1;

    /* Commit the xPAI descriptor LAST (physical 0x100000 = boot logical 0): the boot's update trigger. */
    uint8_t desc[REVERT_DESC_SIZE];
    if (revert_xpai_build(desc, len) != 0)
        return -1;
    if (spi4_write(REVERT_DESC_PHYS, desc, REVERT_DESC_SIZE) != 0)
        return -1;

    uint8_t rb[REVERT_DESC_SIZE];
    if (spi4_read(REVERT_DESC_PHYS, rb, REVERT_DESC_SIZE) != 0)
        return -1;
    for (uint32_t i = 0; i < REVERT_DESC_SIZE; i++)
        if (rb[i] != desc[i])
            return -1;

    return 0;
}

void revert_trigger_reset(void)
{
    AIRCR = 0x05FA0004u;                        /* VECTKEY + SYSRESETREQ (boot f+0x18b6) */
    for (;;) { }
}