/* revert.h — revert-from-custom aid: stage a stock SERVICE.UPG to the SPI update pool + write the
 * boot's xPAI update command, so the next reset installs stock. REPORT §5.15c (analyze108/108b/108c).
 *
 * The boot (sectors 0–4) has NO USB (analyze108: zero OTG-register xrefs); its only update intake is
 * serial XMODEM (§5.15b) and the SPI-flash xPAI command. custom_fw removes the stock usbdisk USB
 * updater, so this module is the app-side revert channel: a USB CDC console (TinyUSB) receives the
 * raw obfuscated SERVICE.UPG, stages it to the SPI update pool, writes the 64-byte xPAI descriptor,
 * and resets. The boot then validates + decodes + installs stock MAINARM verbatim (§5.16).
 *
 * SPI staging layout (2 MB NOR, upper-1 MB update pool; boot f+0x1ace maps logical addr -> physical
 * addr+0x100000, bounds logical < 0x100000):
 *   xPAI descriptor : logical 0x00000  = physical 0x100000  (64 B = 16 LE words)
 *   UPG payload     : logical 0x10000  = physical 0x110000  (raw obfuscated SERVICE.UPG)
 *
 * xPAI descriptor (boot f+0x1108 validation):
 *   word[0]  @+0x00 = 0x49415078 ("xPAI" LE)        magic
 *   word[1]  @+0x04 = 0xABCDEF12                   secondary magic
 *   word[14] @+0x38 = UPG length                   bounds 0x72C <= len <= 0xE0404
 *   word[15] @+0x3C = XOR(words[0..14])            checksum: XOR of all 16 words == 0
 *   words[2..13]    = 0
 *
 * UPG header validation (boot f+0x1eca, on the staged raw bytes):
 *   key0 = upg[0], key1 = upg[1] (both must be nonzero); decode h[i] = upg[2+i]^key0, odd i ^= key1
 *   for i in [0,0x400). Then "XIE2" @ h[0x3E8], CRC16/MODBUS residue 0 over h[0x3E8..0x3FE),
 *   length field h[0x3F0] (LE32) = filesize-0x404, and the boot bound (len-2) > (h[0x3F0]+0x402).
 *
 * BRICK-SAFE: the boot validates the xPAI XOR + the UPG XIE2/CRC BEFORE installing; a bad upload is
 * rejected and the existing app still launches. The pure build/validate/check logic below is
 * host-unit-tested (custom_fw/test_revert.c); the SPI staging + reset path is hardware-only.
 */
#ifndef REVERT_H
#define REVERT_H
#include <stdint.h>

/* SPI update-pool staging addresses (PHYSICAL; the boot adds 0x100000 to its logical addresses). */
#define REVERT_POOL_PHYS      0x100000u  /* update pool base = upper 1 MB of the 2 MB NOR        */
#define REVERT_POOL_SIZE      0x100000u  /* 1 MB pool; boot bounds logical addr < 0x100000       */
#define REVERT_DESC_PHYS      0x100000u  /* xPAI descriptor @ logical 0      (physical 0x100000) */
#define REVERT_UPG_PHYS       0x110000u  /* UPG payload   @ logical 0x10000  (physical 0x110000) */
#define REVERT_DESC_SIZE      64u        /* 16 LE words                                        */

/* xPAI descriptor constants (boot f+0x1108). */
#define REVERT_XPAI_MAGIC     0x49415078u  /* "xPAI" little-endian                              */
#define REVERT_XPAI_MAGIC2    0xABCDEF12u  /* word[1] secondary magic                           */
#define REVERT_LEN_MIN        0x72Cu       /* boot lower bound on word[14]                      */
#define REVERT_LEN_MAX        0xE0404u     /* boot upper bound on word[14]                      */

/* UPG layout constants (make_service_upg.py / boot f+0x1eca; decoded-header offsets). */
#define REVERT_UPG_HDR        0x402u       /* boot strips this header, installs fw[0x402:]      */
#define REVERT_UPG_KEYEcho    2u           /* leading key-echo bytes upg[0],upg[1]              */
#define REVERT_XIE2_OFF       0x3E8u       /* "XIE2" magic in the decoded header                */
#define REVERT_FOOT_CRC_OFF   0x3FCu       /* footer CRC16/MODBUS (LE16) stored @ h[0x3FC]      */
#define REVERT_LEN_OFF        0x3F0u       /* length field (LE32) in the decoded header         */
#define REVERT_FOOT_LO        0x3E8u       /* footer data start (CRC covers [0x3E8,0x3FC))      */
#define REVERT_FOOT_HI        0x3FEu       /* residue end = data+crc ([0x3E8,0x3FE), 0x16 B)    */

/* CRC16/MODBUS: poly 0x8005 reflected 0xA001, init 0xFFFF, refin/refout, xorout 0 (boot f+0x1cc8).
 * Residue over data+crc == 0. Bitwise (no table) — small, host-testable. */
uint16_t revert_crc16_modbus(const uint8_t *d, uint32_t n);

/* xPAI length to stage for a UPG of `filesize` bytes. The boot bound (f+0x1f76) requires
 * (len-2) > (length_field+0x402) with length_field = filesize-0x404, i.e. len > filesize.
 * filesize+2 is the minimal value that passes and decodes the full image. */
uint32_t revert_xpai_len_for(uint32_t filesize);

/* Build the 64-byte xPAI descriptor for a staged UPG of `upg_len` bytes (use revert_xpai_len_for).
 * Returns 0 on success, -1 if upg_len is outside [REVERT_LEN_MIN, REVERT_LEN_MAX]. */
int revert_xpai_build(uint8_t out[REVERT_DESC_SIZE], uint32_t upg_len);

/* Validate a 64-byte xPAI descriptor exactly as the boot f+0x1108 does (magic, magic2, length
 * bounds, XOR-of-16-words == 0). Returns 0 if the boot would accept it, -1 otherwise. */
int revert_xpai_validate(const uint8_t desc[REVERT_DESC_SIZE]);

/* Validate a raw obfuscated UPG header exactly as the boot f+0x1eca does (key-echo nonzero,
 * XOR-decode the 0x400 header, "XIE2" magic, footer CRC16/MODBUS residue 0, length bound).
 * `len` is the xPAI length that WOULD be staged (revert_xpai_len_for(filesize)). Returns 0 if the
 * boot would accept it, -1 otherwise. Does NOT modify `upg`. */
int revert_upg_check(const uint8_t *upg, uint32_t len);

#endif /* REVERT_H */