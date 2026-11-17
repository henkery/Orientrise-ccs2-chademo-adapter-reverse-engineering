# Orientrise CCS2 → CHAdeMO Adapter — Firmware Reverse-Engineering Report

**Target:** `MAIN_CCS2CHADEMO_1[02.01.C009](1).rar` → `MAIN_CCS2CHADEMO_1.UPG` (595 140 bytes)
**Firmware version:** `2.01.C009` · **Build:** `2025-03-03 09:39:39` · **Model:** `KM-CCS2CHAdeMO-1`
**Goal:** understand the vendor update well enough to build an open-source replacement firmware.

> Confidence legend: **[C]** confirmed by direct evidence · **[H]** hypothesis, needs more work.

---

## 1. TL;DR

The `.UPG` is a **2-byte-XOR-obfuscated** image of the **main ARM application** for an
**STM32F4 (Cortex-M4)** based CCS2→CHAdeMO (and CCS2→GB/T) EV charging adapter. It is **not
encrypted with a real cipher** — a trivial repeating XOR (`2B 23`) protects the whole file. Once
decoded it is a plain ARM Thumb-2 firmware image with a readable ASCII header and thousands of
debug strings.

The adapter is a **protocol gateway**:
- **CCS2 / EVSE side:** acts as the *EV* (EVCC) — ISO 15118-2 / DIN 70121 over **HomePlug GreenPHY
  power-line (Qualcomm QCA7005)**, plus CP/PP analog signaling.
- **Vehicle side:** acts as the *charger* — **CHAdeMO** (CAN to the car BMS) and/or **GB/T 27930**.
- Manages the DC power path: connector **e-lock**, **precharge**, **welding detection**,
  **insulation/isolation**, contactor/relay control, emergency shutdown.

Stack: an RTOS + TCP/IP + **mbedTLS** (X.509/PKI for ISO 15118 contract certificates) + SDP/TLS.

---

## 2. Update container format  [C]

### 2.1 Obfuscation
The **entire file** is XORed with a repeating 2-byte key:

```
key = 2B 23        plain[i] = cipher[i] XOR key[i mod 2]
```

How it was found:
- Full-file autocorrelation peaks at every **even** shift → 2-byte period.
- Header known-plaintext (`MAIN_CCS2CHADEMO_1` at offset `0x0C`) yields the key directly.
- Decoding makes `0x00` the most common byte and produces valid ARM code + readable strings.

> Note: a naive "most-common byte = 0x00" attack gives the *wrong* odd key byte (`0x65`), because
> the most common odd-position plaintext byte is `0x46` (Thumb `MOV` high-register opcode), not `0x00`.

### 2.2 Decoded header (first `0x58` bytes)
ASCII lines, each `$$<field>\r\n`, preceded by a 2-byte prefix (`00 2B`):

| field | value | meaning |
|---|---|---|
| `$$DATA` | container magic | |
| `$$MAINARM` | image type | main ARM MCU application |
| `$$2025-03-03 09:39:39` | build timestamp | matches RAR member date |
| `$$2.01.C009` | version | |
| `$$KM-CCS2CHAdeMO-1` | product model | |
| `$$CCS2GBT` | platform/standard tag | shared CCS2/GB/T firmware platform |

### 2.3 Decode it yourself
```bash
nix-shell -p python3 --run 'python3 re/decode_upg.py \
  "extracted/MAIN_CCS2CHADEMO_1.UPG" re/firmware.bin re/strings.txt'
```
`re/decode_upg.py` is a standalone, reusable decoder (XOR + header parse + string dump).

---

## 3. MCU & memory map

### 3.1 Core / architecture  [C]
- **ARM Cortex-M4, Thumb-2** (`mov.w`, `bl`, `cbz/cbnz`, `dsb/isb`, MSR/MRS).
- Startup is position-independent (ADR/ADD relocation loops), zero-fills `.bss`, then jumps to app.

### 3.2 Part family: STM32F4  [C]
Peripheral base addresses found as literals match **STM32F4** exactly (F1/F3 differ):

| address | peripheral | address | peripheral |
|---|---|---|---|
| `0x40023800` | **RCC** (F4-specific) | `0x40023C00` | FLASH interface |
| `0x40020000…0x40021400` | GPIOA…GPIOE | `0x40013800` / `0x40013C00` | SYSCFG / EXTI |
| `0x40006400` / `0x40006800` | **CAN1 / CAN2** | `0x40013000` | **SPI1** |
| `0x40000000` | TIM2 (used heavily) | `0x40010000`/`0x40010400` | TIM1/TIM8 |
| `0x50000000` / `0x40040000` | USB OTG FS / HS | `0xE000E010`/`0xE000ED00` | SysTick / SCB |
| `0x40007000` | PWR | `0x40023000` | CRC |

### 3.3 RAM layout → exact sub-family  [C]
Reset_Handler zero-fills two `.bss` regions:
- `0x20000000`, `0xC000` words = **192 KB** main SRAM
- `0x10000000`, `0x4000` words = **64 KB** CCM RAM

192 KB SRAM + 64 KB CCM ⇒ **STM32F427 / F429 / F437 / F439** class (F405/407 have only 128 KB).
No Ethernet MAC usage seen ⇒ likely **STM32F427/F429**. **[H]** A pin-compatible **GD32F450/470**
cannot be fully excluded without `DBGMCU_IDCODE` / flash-size register reads.

### 3.4 Flash / link base  [C]
- Flash at `0x08000000` (STM32F4). App is **bootloaded**: string `BOOT_CCS2CHADEMO_1.UPG` present.
- **Confirmed via the absolute pointer table in `.rodata`** (§4): the decoded payload maps to
  `address = 0x08020000 + file_offset`. Resolving 231 table pointers against candidate bases gives
  **166/231 landing on real strings at base `0x08020000`** (vs 0–27 for any other base).
- So: file `0x000`→`0x08020000`, **Reset_Handler (file `0x400`)→`0x08020400`**, image end
  (file `0x914C4`)→`0x080B14C4`. The `0x000–0x400` header+prefix occupy `0x08020000–0x08020400`;
  the vector table is placed there by the bootloader decrypting the prefix (§4.1).
- `0x08020000 − 0x08000000 = 0x20000` ⇒ **128 KB bootloader** at `0x08000000–0x08020000`.

---

## 4. Image layout (decoded offsets)

| offset | size | entropy | content |
|---|---|---|---|
| `0x000000–0x000058` | 88 B | text | `$$…` header (§2.2) |
| `0x000058–0x000400` | 936 B | 7.81 | **[C] stream-cipher-encrypted block** = 914 B ciphertext + 22 B plaintext footer (`XIE22.00` + fields). Likely vector table + secure init, decrypted by the bootloader (§4.1) |
| `0x000400–…` | — | code | **Reset_Handler at `0x400`** (= `0x08020400`), then app code + rodata |
| `0x000D00–0x02xxxx` | — | low/med | debug-string tables (SLAC/TCP/TLS/SDP/ISO15118/CHAdeMO/GB/T) |
| `0x067700–0x067C00` | — | code | RCC/FLASH/GPIO/CAN/SPI init (STM32 HAL-style) |
| `0x0738C0–0x073960` | — | code | **[C] QCA7005 SPI1 byte-level host driver** (full-duplex `SPI_DR` exchange, `0xAA`/`0x55` sync, buffer-write loop) |
| `0x08C400–0x08E600` | ~8.7 KB | high | **[C]** mbedTLS crypto tables — AES S-boxes (`0x8C4D6`, `0x8D5D6`), SHA-256 constants (`0x8EB2E`, `0x8F126`); high entropy = fixed lookup tables, not encrypted data. `.rodata` pointer tables start interleaved here (`0x8CCD2`) |
| `0x08E800–0x0914C4` | ~11 KB | very low | **[C] `.rodata` absolute pointer + string tables** — 32-bit flash addresses `0x080Axxxx`/`0x080Bxxxx`, records `{str_ptr, count, ptr, ptr, ptr}`; these pin the link base (§3.4) |

**No Cortex-M vector table in the clear region** and **no `0x200xxxxx` initial-SP word anywhere** ⇒
the vector table is inside the encrypted prefix and is written to the app base (`0x08020000`) by the
bootloader before it jumps to the app. **[H]** (consistent with the confirmed link base, §3.4)

### 4.1 The encrypted prefix (`0x58–0x400`)  [C characterization · H contents]
- **936 B = 914 B ciphertext + 22 B plaintext footer.** Entropy 7.81.
- **Cipher = stream cipher, not XOR / not AES-ECB:** byte autocorrelation is flat (~1/256 at every
  shift 1–64, no key-length peak), there are **no repeated 16-byte blocks** and **no repeated
  32-bit words**. Length is not 16-aligned ⇒ consistent with a keystream (AES-CTR / custom PRNG),
  not a block cipher in ECB.
- **Plaintext footer** (`0x3EA–0x400`):

  | offset | bytes | interpretation |
  |---|---|---|
  | `0x3EA` | `58 49 45 32 32 2E 30 30` | `"XIE22.00"` — format/version tag |
  | `0x3F2` | `C0 10` | `0x10C0` (u16) |
  | `0x3F4` | `09 00 00 00` | `9` (u32) |
  | `0x3F8` | `00…00` | reserved |
  | `0x3FE` | `BE 2D` | `0x2DBE` (u16, likely a checksum; no CRC16 variant over the image matches) |

- **Contents [H]:** almost certainly the Cortex-M **vector table + secure init** (there is no vector
  table anywhere in the clear). The **decryption key/routine is in the bootloader**, not this image,
  so it cannot be decrypted from the `.UPG` alone. For an open firmware this is a non-issue: we
  supply our own vector table.

---

## 5. Software architecture (from strings & code)

### 5.1 RTOS  [C present, H identity]
Preemptive RTOS with named processes and a task-stat dump
(`Task RT BASE IER SS STKF STKS ADDR NAME`). Named processes include:
`tcpip_process`, `led_process`, `PDS_PROCESS`, plus per-protocol state-machine tasks.
Exact RTOS not identified from strings (not FreeRTOS/RT-Thread/uC-OS by name).

### 5.2 Protocol state machines  [C]
- **ISO 15118-2 EVCC** (`iso1_…`): SessionSetup, ServiceDiscovery, PaymentSelection,
  ContractAuthentication, ChargeParameterDiscovery, **CableCheck**, **PreCharge**,
  PowerDelivery, **WeldingDetection**, SessionStop, **CertificateUpdate**, appHandshake.
- **DIN 70121** (legacy DC fallback): "selected DIN70121" / "selected ISO15118".
- **GB/T 27930 DC** (`GBT stm`): CHM/BHM/CRM/BRM/BCP/CTS/CML/CRO/CCS/BST/BSM/BEM, E-lock, A+ signal.
- **GB/T AC** (`GBT AC stm`): SIF/BLM, plug-in/out, E-lock.
- **CHAdeMO** (`CHAdeMO stm`, `CBMS` = CHAdeMO BMS): lock, precharge, welding detection,
  `evcc_ask_bms`, `bms_can_nodata`, emergency shutdown.

### 5.3 PLC / physical layer  [C]
- **Qualcomm QCA7005** HomePlug GreenPHY modem on **SPI1**, driven by a byte-level host driver at
  file `0x738C0–0x73960` (full-duplex `SPI_DR` exchange, `0xAA`/`0x55` sync bytes, buffer-write loop).
- **The QCA7005 firmware is NOT in this update** (§8.6): the version string
  `MAC-QCA7005-1.1.0.727-02-20130826-FINAL` is only a reference/log string inside the SLAC debug
  table; there is **no firmware blob and no host-download routine** ⇒ the modem boots from its **own
  external SPI flash**. The MCU is purely a SLAC/PLC *host*.
- **SLAC** (ISO 15118-3): `CM_SLAC_PARA_REQ/CNF`, `CM_START_ATTEN_CHAR_IND`, `CM_ATTEN_CHAR_RSP`,
  `CM_SLAC_MATCH_CNF`, `SET_KEY_REQ/CNF`, `VS_HST_ACTION_IND`, **BCB toggle**, D_LINK/AVLN manage.
- **SDP** (SECC Discovery Protocol, UDP), **TCP**, **TLS**.

### 5.4 Security / networking  [C]
- **mbedTLS**: `mbedtls_x509_crt_verify`, `pki_crypt_verify_chain`, cert version parsing,
  Netscape cert-type OIDs ⇒ ISO 15118 contract/SECC certificate chain validation.
- TCP/IP stack (likely **lwIP** **[H]**), TLS client, SDP.

### 5.5 Analog / power control  [C]
- **CP** states A–F + duty-cycle read (`CP DUTY is '%c'…`), **PP** (proximity), `KEY_LOCK`.
- Connector **e-lock**, **precharge**, **welding detection**, **insulation/isolation**,
  contactor/relay drive (`precharge_relay failed!terminate`), emergency/timeout shutdown.
- **TIM2** used heavily (16 refs) ⇒ likely CP PWM capture/compare. **CAN1/CAN2** ⇒ CHAdeMO + GB/T BMS.

### 5.6 Self-update mechanism — `usbdisk` process  [C machinery · H orchestration]

**The USB/FAT32/UPG updater is (at least partly) IN THIS MAINARM APP**, not only a pre-boot. The app
contains a complete `usbdisk` process:

- **USB host mass-storage**: ST **USBH** library (`USB host library started`, `Mass storage device
  connected`, `VID/PID`, `Enumeration completed`, `Overcurrent detected`) + **BOT** (`USBC`/`USBS` =
  CBW/CSW signatures @`0x388B6`/`0x388C2`), SCSI `READ CAPACITY` (`Disk capacity: block number…`).
- **FatFs** (FAT16/FAT32): `MSDOS5.0`, `NO NAME    FAT`/`FAT32` (mkfs BPB templates @`0x3733D…`),
  drive path `0:/`, `Cannot initialize File System.`
- **UPG handling**: looks for the exact root filenames **`MAIN_CCS2CHADEMO_1.UPG`**,
  **`MAIN_CCS2CHADEMO_1_ID6.UPG`** (hardware-rev variant) and **`BOOT_CCS2CHADEMO_1.UPG`**;
  `file Open/Read/size error`, `'%s' has been updated`, `[%t]UPGRADE Finished`, `Write flash error[%u]`;
  parses the UPG header version+date (`UPGRADE:[%u]%c%c… 20%02X-%02X-%02X …`).
- **Flash writer** (file `0x91020–0x91184`): correct STM32F4 HAL-style **unlock** (`FLASH_KEYR`←
  `0x45670123`/`0xCDEF89AB`) → **sector erase** (`FLASH_CR=SER|SNB|STRT`) → **program word** (`PG`, x32)
  with **read-back verify** → **lock**. Validates `sector<12`. It is stored at `0x080B10AC` (**inside
  the app's own sector 9**) and is called **indirectly via a function pointer** ⇒ it is **copied to and
  executed from SRAM** to self-flash. Uses a 12-entry sector size/start table (`0x9119E`/`0x911CE`).
- **Reboot**: `NVIC_SystemReset` (SCB_AIRCR `0xE000ED0C` ← `0x05FA0004`) present @`0x67C2E`.
- Same module also **exports** `EVCC_%s_INFO.TXT` (HW/SW/SER/RTC) and `EVCC_%s_LOGS.BIN` to the stick.

**Flash map (1 MB, 12 sectors — from the writer's own tables):**

| sectors | address | size | role |
|---|---|---|---|
| 0–4 | `0x08000000–0x08020000` | 128 KB | **bootloader** (separate `BOOT_…UPG`) |
| 5–9 | `0x08020000–0x080C0000` | 640 KB | **main app** (this image, 595 KB) |
| 10–11 | `0x080C0000–0x08100000` | 256 KB | logs / config (`EVCC…LOGS`) |

⇒ 1 MB flash + 192 KB SRAM + 64 KB CCM ⇒ **STM32F427/F429 “G” (1 MB)** part **[H, needs DBGMCU]**.

**Split of duties [H, strong]:** the **XOR key `2B 23` and the prefix stream-cipher key are NOT anywhere
in this app** (no `movw 0x232B`, no key data, no `$$DATA`/`$$MAINARM` magic strings). So the app reads
the UPG and writes it to flash **in its raw/obfuscated form**, then resets; the **bootloader performs the
XOR-decode + prefix-decrypt (+ likely verify) and installs/launches the app**. The decode/decrypt keys
live in the bootloader, which is **not** part of this update.

**Bricking-safety read:**
- **In-place self-update, no A/B / staging** (app+logs fill the 1 MB). App erases its own sectors 5–9.
- **Bootloader (sectors 0–4) is NOT touched by a MAIN update ⇒ it survives** a failed app update and is
  the **recovery anchor**. Whether it has a USB/SWD recovery mode is **unknown** (bootloader not in hand).
- Integrity: **per-word read-back verify** in the writer; **no whole-image pre-write CRC/signature seen
  in the app** (any such check would be bootloader-side).
- The app can also flash **`BOOT_…UPG`** (bootloader self-update) — **riskier**, it overwrites the
  recovery anchor itself.

### 5.7 Bootloader acquisition — bricking-safe SWD read  [C procedure]

The bootloader (§8.2b) is not in hand; the non-destructive way to obtain it is a **SWD flash read** of
`0x08000000–0x08020000`. Key safety fact: **reading flash never triggers a mass-erase.** On STM32F4 the
erase fires **only on an RDP Level 1→0 regression** (an explicit "unlock / remove-protection" *write*):

| RDP level | SWD read flash | outcome |
|---|---|---|
| 0 (`0xAA`) | ✅ | dump works, no erase |
| 1 (any other byte) | ❌ blocked | read fails harmlessly — **no erase** |
| 2 (`0xCC`) | ❌ SWD disabled | can't connect; irreversible |

**Probe before dumping:** read the first 8 bytes at `0x08000000`. A sane vector table (word0 = initial SP
`0x200xxxxx`, word1 = reset vector `0x0800xxxx`|1) ⇒ **Level 0, safe to dump**; error / all-zeros ⇒
**Level 1/2 — stop and use the vendor email** (§8.2b). **Never run an unlock / mass-erase command** — that
is the only thing that wipes the recovery anchor.

**Probe hardware (user bench):** an **ESP32-S3** flashed with **`fl4p/daplink-s3`** becomes a 3.3 V USB
**CMSIS-DAP** probe — OpenOCD `interface/cmsis-dap.cfg` + `transport select swd` + `target/stm32f4x.cfg`,
then `dump_image boot.bin 0x08000000 0x20000` (raw read, non-destructive). A cheap **ST-Link V2 clone** is
the easiest alternative (`st-flash read boot.bin 0x08000000 0x20000`). The Arduino Mega (5 V AVR) is
unsuitable. **SWD pins:** SWDIO=**PA13**, SWCLK=**PA14**, +GND and NRST (for connect-under-reset if the app
reuses PA13/14 or sleeps); physical pin numbers are package-dependent (read the MCU marking, §8.1).
⚠️ **Bench only:** HV side disconnected & capacitors discharged; SWD is in the 3.3 V MCU domain — keep clear
of the up-to-1000 V power section.

---

## 6. What this means for an open-source firmware

You do **not** need to break any crypto — the "protection" is a 2-byte XOR. The hard part is the
protocol + hardware bring-up, and most of it has open building blocks:

| layer | vendor uses | open-source path |
|---|---|---|
| MCU BSP | STM32F4 HAL | **libopencm3**, STM32CubeF4, **Zephyr**, or **RT-Thread** (all support F427/F429) |
| RTOS | unidentified | FreeRTOS / Zephyr / RT-Thread |
| TCP/IP | (lwIP?) | **lwIP** |
| TLS/PKI | mbedTLS | **mbedTLS** (drop-in) |
| PLC modem | QCA7005 on SPI1 (fw in external flash) | **open-plc-utils** (Qualcomm) + Linux `qca_spi` as reference; QCA7005 firmware is a separate redistributable blob — **not present in this update**, nothing to extract |
| SLAC | custom | ISO 15118-3 SLAC; reference impls in open EVSE/EVCC projects |
| ISO15118/DIN70121 EVCC | custom | **OpenV2G** (EXI), open EVCC stacks (e.g. ChargeControl / Vector-style, Python/C ISO15118 libs) |
| CHAdeMO | custom CAN | CHAdeMO CAN spec; OpenInverter community impls |
| GB/T 27930 | custom CAN | GB/T 27930 CAN spec (message set already enumerated in §5.2) |

**Recommended approach:** build a fresh firmware on the same MCU (STM32F427/F429) reusing the
*hardware design* (QCA7005 on SPI1, CAN1/CAN2 for BMS, TIM2 for CP, GPIO for relays/lock/PP), and
re-implement the protocol gateway with the open blocks above. The vendor image is a gold-mine of
**timing constants, state transitions, CAN message layouts and error handling** to validate against.

> **Prior-art check (2026-11-17):** the open **ccs32clara** project (`uhi22/ccs32clara`,
> `osexpert/ccs32clara-chademo`) targets the *Dongguan Longood* CCS2→CHAdeMO adapter (STM32F407 +
> QCA7000, bit-banged SPI, plain `My407ccs2chademo.bin` USB update; libopencm3 + libopeninv; OpenInverter
> forum t=3727) and **explicitly excludes Orientrise as incompatible**. It is a useful *reference* for
> EXI/SLAC/CHAdeMO state machines and bring-up, but **not a drop-in** for this F427/F429 `.UPG` platform
> — our RE remains the basis. It also confirms the bootloader-centric update model (§5.6) on that OEM HW.

---

## 7. Artifacts produced (in `re/`)

- `decode_upg.py` — reusable decoder (XOR + header + strings).
- `firmware.bin` — fully decoded image (595 140 B).
- `strings.txt` — 2 724 unique strings ≥6 chars, with offsets.
- `decoded23.bin` — same decoded image (analysis copy).
- `analyze1.py … analyze26.py` — the analysis trail (entropy, autocorr, key recovery, vector/peripheral
  scans; **15–18** = prefix cipher / QCA-blob / link-base; **19–24** = `usbdisk` update module, flash
  writer, sector tables, XOR-key absence, flash-writer call graph; **25–26** = bootloader search /
  vector-table scan — **negative**, no embedded bootloader).
- `REPORT.md` — this document.

## 8. Open questions / next steps

1. **Exact MCU part** — narrowed to **STM32F427/F429, 1 MB flash** (flash-writer’s 12-sector table, §5.6) + 192 KB SRAM + 64 KB CCM. Easiest: **read the MCU top marking** (e.g. `STM32F427VGT6`: V=LQFP100 / Z=LQFP144, G=1 MB) — this also gives the package needed for SWD pin numbers (§5.7). Else confirm via `DBGMCU_IDCODE` (`0xE0042000`, read by the app) / flash-size reg (`0x1FFF7A22`).
2. **App link base** — **CONFIRMED `0x08020000`** via the `.rodata` pointer table (§3.4). Remaining: obtain `BOOT_CCS2CHADEMO_1.UPG` to see how the prefix/vector table is decrypted & placed, and to recover the prefix keystream/key.
2b. **Bootloader / update orchestration (bricking-critical)** — **SEARCHED, NOT FOUND (2026-11-17).** The bootloader is a separate factory component at `0x08000000–0x08020000` (128 KB, sectors 0–4). It is **not in the RAR** (only `MAIN_…UPG`), **not elsewhere in the project**, and **not embedded in the app** — no real vector table; the lone `0x8F652` candidate is a misaligned `.rodata` pointer-table false positive (`analyze25/26`). **Not publicly downloadable:** vendor **Orientrise** (No. 355 Longjin Rd, Changzhou, Jiangsu) ships firmware **contact-only** — `support@orientrise.net` / `sales@orientrise.net`, phone/WhatsApp/WeChat `+86 181 0150 7071`; free firmware on request matched to vehicle/region, **no self-service portal and no `BOOT_…UPG` published**. The nearest open project **`uhi22/ccs32clara` / `osexpert/ccs32clara-chademo`** (Dongguan **Longood** OEM + rebrands EV-Boy / Akyga AK-SC-E18 / EVniculus / Autonlaturit) **explicitly lists Orientrise as NOT compatible** (Longood = STM32F407 + plain `My407ccs2chademo.bin`; Orientrise = F427/F429 + `.UPG`/XOR/encrypted prefix) and does **not** include its own OEM bootloader either — but its README independently corroborates §5.6: *"Firmware update logic is inside the bootloader, so this is not affected by the firmware."* **Acquisition paths:** (a) **email the vendor** for `BOOT_CCS2CHADEMO_1.UPG`; (b) **SWD dump** of `0x08000000` len `0x20000` — **bricking-safe procedure in §5.7** (ESP32-S3 CMSIS-DAP or ST-Link): reading is non-destructive at any RDP level, only an RDP 1→0 *unlock* erases — **never unlock**; probe the first 8 bytes to learn the level first. Once obtained, confirm: who reads USB first, the XOR/prefix decode + any whole-image verify, and any USB/SWD recovery mode.
3. **The prefix block** (`0x58–0x400`) — **characterized** (§4.1): stream-cipher ciphertext (914 B) + plaintext footer `XIE22.00` / `0x10C0` / `9` / `0x2DBE`. Key/routine lives in the bootloader, not this image. *(The `0x8C400–0x8E600` block is mbedTLS AES/SHA-256 tables, not encrypted data.)*
4. **Pin map** — disassemble the GPIO init table (`0x67756…`) to map relays, e-lock, CP/PP ADC, QCA7005 SPI pins, CAN pins.
5. **CAN IDs & timing** — extract CHAdeMO/GB/T CAN identifiers, baud rates, and protocol timeouts from the state machines.
6. **QCA7005 firmware** — **RESOLVED: not in this update.** Modem boots from external SPI flash; the MCU is only a SLAC/PLC host (§5.3). For open firmware, use the redistributable Qualcomm blob (open-plc-utils / `qca_spi` ecosystem).
7. **RTOS identity** — locate the scheduler/task code to name the RTOS.