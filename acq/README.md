# acq/ — non-destructive bootloader & flash acquisition kit

**Goal:** obtain the missing **bootloader** (`0x08000000–0x08020000`, 128 KB, sectors 0–4)
plus the full flash, option bytes and UID — the piece REPORT §8.2b says is *searched, not
found*. This unblocks (a) confirming the app-launch / prefix-decrypt convention (§4.1) and
(b) building a bootable minimal **service firmware** (boot + flasher + dumper).

Everything here is **READ-ONLY**. No script unlocks, erases, or writes the target.

---

## ⚠️ Safety — read first

- **Bench only.** HV power section **disconnected**, bulk capacitors **discharged**. SWD/UART/USB
  are in the **3.3 V MCU domain** — keep clear of the up-to-1000 V power stage (REPORT §5.7).
- **The golden rule: reading flash never mass-erases.** On STM32F4 the erase fires **only** on an
  **RDP Level 1→0 regression** — an explicit *unlock / remove-protection* **write**. We never issue one.

  | RDP level | SWD / system-boot **read** | outcome |
  |---|---|---|
  | 0 (`0xAA`) | ✅ works | dump succeeds, **no erase** |
  | 1 (other) | ❌ blocked | read fails **harmlessly** — no erase. **STOP, never unlock.** |
  | 2 (`0xCC`) | ❌ SWD off | can't connect; irreversible |

- **NEVER run these** (they erase / brick the recovery anchor):
  - OpenOCD: `stm32f2x unlock`, `stm32f2x mass_erase`, `stm32f2x options_write`, `flash erase_*`, `flash write_*`
    (OpenOCD drives F4 flash with the shared **`stm32f2x`** driver — not `stm32f4x`)
  - stm32flash: `-k` (disable read-protection → **mass-erase**), `-j`, `-u`, `-o`, `-e`, `-w`, `-g`
  - dfu-util: `-D` (download), `-s …:unprotect`, `-s …:mass-erase`, `-s …:force`
- **Probe before dumping.** The SWD script reads the first 8 bytes at `0x08000000` and **refuses to
  dump** unless they look like a sane vector table (word0 = initial SP `0x200xxxxx`/`0x100xxxxx`,
  word1 = reset vector `0x0800xxxx|1`). Garbage/zeros/error ⇒ RDP1/2 ⇒ stop.

---

## Step 0 — identify the hardware

1. **Read the MCU top marking** (REPORT §8.1), e.g. `STM32F427VGT6` → V=LQFP100 / Z=LQFP144, G=1 MB.
   This gives the package ⇒ physical pin numbers for the pads below.
2. **Locate pads / headers:**
   - **SWD:** SWDIO=**PA13**, SWCLK=**PA14**, **GND**, **NRST**, 3V3 (sense). NRST enables
     connect-under-reset (needed if the app reuses PA13/14 or sleeps).
   - **BOOT0** (pull to 3V3 to enter the ST system bootloader; often tied low via a resistor).
   - **UART1:** TX=**PA9**, RX=**PA10** (usual F427/F429 system-bootloader UART; confirm per **AN2606**).
   - **USB OTG FS** (the app's USB-A host port; DFU device mode may not be exposed — see Path C).

---

## Path A — SWD via ESP32-S3 CMSIS-DAP  *(primary, recommended)*

Uses the bench **ESP32-S3** flashed with **`fl4p/daplink-s3`** → a 3.3 V USB **CMSIS-DAP v2** probe.

1. Flash `daplink-s3` onto the ESP32-S3 (per that project's instructions); it enumerates as a
   CMSIS-DAP USB device.
2. Wire SWDIO/SWCLK/GND/NRST/3V3 to the target pads.
3. **USB permissions (NixOS):** OpenOCD needs access to the probe. Either install its udev rules
   (`services.udev.packages = [ pkgs.openocd ];` then replug) or run the script with `sudo`.
   `LIBUSB_ERROR_ACCESS` / "Permission denied" ⇒ this is the cause.
4. Run:
   ```bash
   ./acq/swd_dump.sh                 # dumps into acq/dump/
   # SWD_NO_RESET=1 ./acq/swd_dump.sh   # if NRST is not wired
   # ADAPTER_SPEED=480 ./acq/swd_dump.sh # if the link is unstable
   ```
   The script (`swd_dump.tcl`) does, in order: `reset halt` → `options_read` (RDP) →
   `DBGMCU_IDCODE`/UID/flash-size → **probe gate** → `dump_image` of `boot.bin` (0x20000),
   `flash_full.bin` (0x100000), `optbytes.bin`, `uid.bin`. All output is tee'd to `openocd_log.txt`.

**Why SWD first:** it's the most reliable, gives the exact part (`DBGMCU_IDCODE` DEV_ID `0x419`
for F427/F429), the RDP level (option bytes), and a clean full-flash image — and it's reversible.

---

## Path B — UART via ST system bootloader  *(probe-free fallback)*

No SWD probe needed — just BOOT0 + a 3.3 V USB-UART bridge.

1. **BOOT0 = 1**, reset the target ⇒ ST **system bootloader** (AN2606) runs on UART.
2. Bridge: **ESP32-S3 flashed as a USB-CDC↔UART bridge** (3.3 V), or a dedicated 3.3 V USB-UART
   (CP2102/FT232). **Avoid the 5 V Arduino Mega** on the 3.3 V MCU. Wire bridge-TX→PA10(RX),
   bridge-RX→PA9(TX), GND.
3. Run:
   ```bash
   ./acq/uart_dump.sh /dev/ttyACM0     # or /dev/ttyUSB0
   ```
   Bare-port probe prints chip id / flash size / **read-protection state**; then `-r … -S addr:len`
   dumps `boot.bin` + `flash_full.bin`. **Requires RDP0** (the system bootloader blocks reads at RDP1).

---

## Path C — USB DFU via ST system bootloader  *(probe-free fallback)*

1. **BOOT0 = 1**, reset, connect **USB OTG FS**. The ST DFU device enumerates as **`0483:df11`**.
2. Run:
   ```bash
   ./acq/dfu_dump.sh
   ```
   `dfu-util -l` lists devices; `-U … -s addr:len -a 0` uploads (reads) `boot.bin` + `flash_full.bin`.
3. **Caveat:** the app uses this port as **USB host** (USB-A stick). DFU **device** mode may not be
   wired on a host-only connector. If `dfu-util -l` shows no `0483:df11`, **use Path B (UART)**.
   Requires RDP0.

---

## What you get (in `acq/dump/`)

| file | region | size | use |
|---|---|---|---|
| `boot.bin` | `0x08000000` | 128 KB | **the bootloader** — the acquisition goal |
| `flash_full.bin` | `0x08000000` | 1 MB | bootloader + app + logs/config (per-unit MAC/certs may live in sectors 10–11) |
| `optbytes.bin` | `0x1FFFC000` | 32 B | RDP level, WRP, nBOOT, BOR |
| `uid.bin` | `0x1FFF7A10` | 20 B | 96-bit UID + flash-size word |
| `*_log.txt` | — | — | probe / option-byte / IDCODE output |

> Dumps are binary artifacts (like `firmware.bin`); they land in `acq/dump/` and are not auto-committed.

## Verify + reverse the dump

```bash
nix-shell -p python3 python3Packages.capstone --run 'python3 acq/analyze_boot.py acq/dump/boot.bin'
```
`analyze_boot.py` (READ-ONLY): vector-table sanity → reset/startup disassembly → hunts for the
XOR key `2B 23`, `$$DATA/$$MAINARM/$$BOOT` magic, `XIE22.00` prefix footer, `FLASH_KEYR` constants,
app-launch words in `0x08020000..0x080C0000`, peripheral bases, and USB/DFU/recovery strings.
Feed findings back into REPORT §5.6 / §8.2b (who reads USB first, XOR/prefix decode + verify,
any recovery mode, and the exact app-launch convention).

## After acquisition → build the service firmware

With `boot.bin` in hand you know the launch convention and can extract the prefix key, so the
minimal **service firmware** (boot + flasher + dumper) becomes buildable *and* bootable — either
SWD-flashed at `0x08000000` (reversible, `boot.bin` backed up) or packaged as a vendor-compatible
`.UPG`. See REPORT §6. **Dump first, build second.**

---

## NixOS / troubleshooting

- All tools come via `nix-shell` (verified: **openocd 0.12.0, stm32flash 0.7, dfu-util 0.11**):
  `nix-shell -p openocd stm32flash dfu-util --run '…'`. Nothing is assumed on PATH.
- **No SWD connection:** check wiring/GND, try `ADAPTER_SPEED=480`, ensure NRST for
  connect-under-reset, confirm the ESP32-S3 actually runs `daplink-s3` (CMSIS-DAP v2).
- **`LIBUSB_ERROR_ACCESS`:** udev rules or `sudo` (Path A step 3).
- **Probe fails / reads all `0x00` or `0xFF`:** RDP1/2 — **stop**. Do **not** unlock. Fall back to
  the vendor `BOOT_CCS2CHADEMO_1.UPG` (REPORT §8.2b: `support@orientrise.net`).
- **DFU not listed:** host-only USB port ⇒ use UART (Path B).
