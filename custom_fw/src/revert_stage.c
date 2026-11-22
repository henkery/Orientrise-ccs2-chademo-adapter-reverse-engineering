/* revert_stage.c — hardware staging path for the revert-from-custom aid (REPORT §5.15c).
 *
 * Sequence (brick-safe):
 *   1. revert_upg_check  — boot-mirror header validation of the uploaded raw UPG (f+0x1eca).
 *   2. revert_xpai_build — 64-byte xPAI descriptor (f+0x1108), len = filesize+2 (boot bound f+0x1f76).
 *   3. spi4_write        — stage the raw UPG to physical 0x110000 (boot logical 0x10000).
 *   4. read-back verify  — chunked spi4_read + compare of the whole staged UPG.
 *   5. spi4_write        — write the xPAI descriptor to physical 0x100000 LAST, then read-back verify.
 *   6. revert_trigger_reset — AIRCR SYSRESETREQ (f+0x18b6); the boot validates + installs stock.
 *
 * The descriptor is committed only after the full UPG is staged AND verified, so a failed upload
 * never leaves a valid update command — the boot launches the existing app (no brick). The boot
 * additionally validates the xPAI XOR + the UPG XIE2/CRC before installing (§5.15c).
 */
#include "revert_stage.h"
#include "revert.h"
#include "spi4.h"

#define AIRCR (*(volatile uint32_t *)0xE000ED0Cu)

/* Chunked read-back verify (no full-image RAM buffer): read 4 KB at a time and compare. */
static int verify_readback(uint32_t phys, const uint8_t *src, uint32_t len)
{
    static uint8_t buf[0x1000];
    uint32_t off = 0;
    while (off < len) {
        uint32_t n = len - off;
        if (n > sizeof buf)
            n = sizeof buf;
        if (spi4_read(phys + off, buf, n) != 0)
            return -1;
        for (uint32_t i = 0; i < n; i++)
            if (buf[i] != src[off + i])
                return -1;
        off += n;
    }
    return 0;
}

int revert_stage(const uint8_t *upg, uint32_t filesize)
{
    if (!upg)
        return -1;

    uint32_t len = revert_xpai_len_for(filesize);
    if (revert_upg_check(upg, len) != 0)        /* boot f+0x1eca header validation */
        return -1;

    uint8_t desc[REVERT_DESC_SIZE];
    if (revert_xpai_build(desc, len) != 0)      /* boot f+0x1108 descriptor */
        return -1;

    /* Stage the raw UPG payload first (physical 0x110000 = boot logical 0x10000). */
    if (spi4_write(REVERT_UPG_PHYS, upg, filesize) != 0)
        return -1;
    if (verify_readback(REVERT_UPG_PHYS, upg, filesize) != 0)
        return -1;

    /* Commit the xPAI descriptor LAST (physical 0x100000 = boot logical 0): this is what the boot
     * keys on. Writing it only after the UPG is staged + verified keeps a partial upload brick-safe. */
    if (spi4_write(REVERT_DESC_PHYS, desc, REVERT_DESC_SIZE) != 0)
        return -1;
    if (verify_readback(REVERT_DESC_PHYS, desc, REVERT_DESC_SIZE) != 0)
        return -1;

    return 0;
}

void revert_trigger_reset(void)
{
    AIRCR = 0x05FA0004u;                        /* VECTKEY + SYSRESETREQ (boot f+0x18b6) */
    for (;;) { }
}