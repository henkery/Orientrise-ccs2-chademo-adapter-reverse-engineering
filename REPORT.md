# Orientrise CCS2 → CHAdeMO Adapter — Firmware Reverse-Engineering Report

**Target:** `MAIN_CCS2CHADEMO_1[02.01.C009](1).rar` → `MAIN_CCS2CHADEMO_1.UPG` (595 140 bytes)
**Firmware version:** `2.01.C009` · **Build:** `2025-03-03 09:39:39` · **Model:** `KM-CCS2CHAdeMO-1`
**Goal:** understand the vendor update well enough to build an open-source replacement firmware.

> Confidence legend: **[C]** confirmed by direct evidence · **[H]** hypothesis, needs more work.

---

## 1. TL;DR

The `.UPG` is a **2-byte-XOR-obfuscated** image of the **main ARM application** for an
**STM32F4 (Cortex-M4)** based CCS2→CHAdeMO (and CCS2→GB/T) EV charging adapter. It is **not
encrypted with a real cipher** — a trivial repeating 2-byte XOR protects the whole file, and the
key is **self-described in the first two bytes** (C009 = `2B 23`, C013 = `25 A8`; §2.1). Once
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

### 2.1 Obfuscation — self-describing 2-byte XOR key
The **entire file** is XORed with a repeating 2-byte key, and **the key is carried in the first two
raw bytes** — so it can differ per revision without any hardcoded secret in the updater/bootloader:

```
key[0] = raw[0]        key[1] = raw[0] XOR raw[1]
plain[i] = cipher[i] XOR key[i mod 2]    (payload from offset 2; offset 2 uses key[0])
```

Equivalently: a 2-byte plaintext key header `[key0, key0^key1]` followed by the XOR-obfuscated
payload (`$$DATA…` header + encrypted prefix + app). Verified on the authentic raw UPGs of two
revisions — the derived key reproduces each known-good decoded image **byte-for-byte**:

| revision | raw[0:2] | key[0]=raw[0] | key[1]=raw[0]^raw[1] | key |
|---|---|---|---|---|
| C009 | `2B 08` | `2B` | `2B^08 = 23` | `2B 23` |
| C013 | `25 8D` | `25` | `25^8D = A8` | `25 A8` |

`decode_upg.py` auto-derives the key from `raw[0:2]` (no hardcoded key). The outer XOR key changing
between revisions is therefore **normal and not a compatibility barrier** — the decoder reads it from
each image. The fixed secret that actually gates compatibility is the **prefix stream-cipher key** in
the bootloader (§4.1 / §5.6).

How the 2-byte period was originally found (C009):
- Full-file autocorrelation peaks at every **even** shift → 2-byte period.
- Header known-plaintext (`MAIN_CCS2CHADEMO_1` at offset `0x0C`) yields the key directly.
- Decoding makes `0x00` the most common byte and produces valid ARM code + readable strings.

> Note: a naive "most-common byte = 0x00" attack gives the *wrong* odd key byte (`0x65`), because
> the most common odd-position plaintext byte is `0x46` (Thumb `MOV` high-register opcode), not `0x00`.

### 2.2 Decoded header (first `0x58` bytes)
ASCII lines, each `$$<field>\r\n`, preceded by a 2-byte prefix `00 <key[0]>` (`00 2B` for C009,
`00 25` for C013 — the second byte is the XOR key's first byte, §2.1):

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
- So: file `0x000`→`0x08020000`, **app code start (file `0x400`)→`0x08020400`**, image end
  (file `0x914C4`)→`0x080B14C4`. The `0x000–0x400` header+prefix occupy `0x08020000–0x08020400`;
  the vector table is placed there by the bootloader decrypting the prefix (§4.1). **Note:** file
  `0x400` is a 10-byte entry *header*, not code — the actual Reset_Handler is at file `0x40A`
  (`0x0802040A`); the reset vector in the decrypted prefix targets it (§5.12).
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
  | `0x3F2` | `C0 10 09 00` | **u32 app-code length** = `0x000910C0` = 594112 = **filesize − 0x404** |
  | `0x3F6` | `00…00` | reserved (zero) |
  | `0x3FE` | `BE 2D` | `0x2DBE` = **CRC16/MODBUS**(`dec[0x3EA:0x3FE]`) — cracked, §5.13 |

  **The `0x3F2` field is a u32 LENGTH, not "u16 `0x10C0` + u32 `9`"** (the `09` at `0x3F4` is just its
  high byte): it equals **filesize − 0x404** in *both* revisions — C009 `0x000910C0` = 594112, C013
  `0x00092208` = 598536 — i.e. the code payload `[0x400, end−4)`. This is exactly the number printed in
  the boot log `UPGRADE:[594112]…` (§5.10). **C013's footer differs only in this length and the `0x3FE`
  u16** (`A8 0B` = `0x0BA8`); `"XIE22.00"` is constant. So the footer carries per-image length + a check
  value, not a fixed key; the prefix **stream-cipher key** is the constant bootloader secret (§5.6).
  **Integrity fields cracked (§5.13, `analyze52/54`):** the footer u16 `0x3FE` =
  **CRC16/MODBUS**(`dec[0x3EA:0x3FE]`) and the trailer u16LE @`n−2` = **CRC16/MODBUS**(`dec[2:n−2]`),
  with `dec[n−4:n−2] == 00 00` (key echo) — verified on **both** revisions. MODBUS = poly `0x8005`
  reflected (`0xA001`), init `0xFFFF`, refin/refout true, xorout 0. The first-4-bytes at `0x400` are
  **not** a CRC of any region — a per-image IV/nonce (§5.12). Both CRCs are recomputable, so a
  patched/extended image can be re-sealed (`make_service_upg.py`, §5.13). The earlier "no standard CRC"
  result (`analyze44/47/49/50`) missed MODBUS because it tested the wrong byte ranges / init values.

- **Contents [H]:** almost certainly the Cortex-M **vector table + secure init** (there is no vector
  table anywhere in the clear). The **decryption key/routine is in the bootloader**, not this image,
  so it cannot be decrypted from the `.UPG` alone — but the bootloader is now acquired (§5.14), so the
  key/routine is recoverable from `acq/dump/boot.bin`. For an open firmware this is a non-issue: we
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
  **Caveat (§5.13):** its literal pools are **+2-byte packed** in the stored image (e.g. the unlock keys
  sit at file `0x9118E`/`0x91192` but the LDR-literals reference `0x9118C`/`0x91190`), so it is **not
  directly executable from the file bytes** — the pools are fixed up at runtime (encoded-overlay).
- **Reboot**: `NVIC_SystemReset` (SCB_AIRCR `0xE000ED0C` ← `0x05FA0004`) present @`0x67C2E`.
- Same module also **exports** `EVCC_%s_INFO.TXT` (HW/SW/SER/RTC) and `EVCC_%s_LOGS.BIN` to the stick.

**Flash map (1 MB, 12 sectors — from the writer's own tables):**

| sectors | address | size | role |
|---|---|---|---|
| 0–4 | `0x08000000–0x08020000` | 128 KB | **bootloader** (separate `BOOT_…UPG`) |
| 5–9 | `0x08020000–0x080C0000` | 640 KB | **main app** (this image, 595 KB) |
| 10–11 | `0x080C0000–0x08100000` | 256 KB | logs / config (`EVCC…LOGS`) |

⇒ 1 MB flash + 192 KB SRAM + 64 KB CCM ⇒ **STM32F427/F429 “G” (1 MB)** part **[H, needs DBGMCU]**.

**Split of duties [H, strong — refined 2026-11-18]:** the **outer XOR key is not a hardcoded secret
anywhere** — it is **self-described in the UPG's first two bytes** (`key0=raw[0]`, `key1=raw[0]^raw[1]`,
§2.1) and varies per revision (C009 `2B 23`, C013 `25 A8`). The app has no `movw 0x232B` / key constant
because it doesn't need one: it reads the key from the image (it already parses the header for the
`UPGRADE:[%u]…` version/date log). The **prefix stream-cipher key**, by contrast, **is** a fixed secret
living in the **bootloader** (not in this app, not in the update). So the app reads the UPG and writes it
to flash **in its raw/obfuscated form**, then resets; the **bootloader performs the prefix-decrypt
(+ likely verify) and installs/launches the app** (the outer XOR-decode can be done by either side from
the self-described key). **The outer-key change across revisions is therefore not a compatibility
barrier; the prefix key + any version/hardware check are the real gates** — now traceable on the acquired
bootloader dump (§5.14).

**Bricking-safety read:**
- **In-place self-update, no A/B / staging** (app+logs fill the 1 MB). App erases its own sectors 5–9.
- **Bootloader (sectors 0–4) is NOT touched by a MAIN update ⇒ it survives** a failed app update and is
  the **recovery anchor**. It has a **USB update path and XMODEM-1K serial recovery** (bootloader acquired,
  §5.14); SWD read is non-destructive at RDP0 (§5.7).
- Integrity: **per-word read-back verify** in the writer; **the app does NOT verify a whole-image
  checksum** — no CRC32 routine exists in the app, and the UPG trailing bytes are CRC16/MODBUS
  integrity *metadata* (§5.13), recomputable, not a gate the app enforces. Any whole-image verify or
  signature check would be **bootloader-side** (boot-time), not in this updater.
- The app can also flash **`BOOT_…UPG`** (bootloader self-update) — **riskier**, it overwrites the
  recovery anchor itself.

### 5.7 Bootloader acquisition — bricking-safe SWD read  [C procedure]

The bootloader is **already acquired** non-invasively via the dump cave (§5.14, `acq/dump/boot.bin`); this
SWD procedure is retained as an **alternative** non-destructive read path (and the way to re-dump or read
other regions). The read targets `0x08000000–0x08020000`. Key safety fact: **reading flash never triggers
a mass-erase.** On STM32F4 the
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

> **Implemented (2026-11-18):** the read-only, probe-gated **`acq/` kit** (§7) — `swd_dump.sh` / `swd_dump.tcl`
> (ESP32-S3 CMSIS-DAP + OpenOCD), UART (`stm32flash`) / USB-DFU (`dfu-util`) system-bootloader fallbacks,
> and `analyze_boot.py` triage. Never unlocks/erases/writes; refuses to dump on RDP1/2. See `acq/README.md`.

### 5.8 CAN bus deep-dive — identifiers, baud rates, timing  [C/H]

The adapter drives **two independent vehicle-side CAN buses** (STM32 bxCAN **CAN1** `0x40006400`,
**CAN2** `0x40006800`): **CHAdeMO** (11-bit IDs, 500 kbit/s) and **GB/T 27930** (29-bit SAE J1939 IDs,
250 kbit/s). The driver reaches the peripherals through a **base-pointer + register-offset** handle
table — there are no absolute `0x40006400` loads in code; the bases live in a 12-byte-stride peripheral
handle table at `0x67B74` (this is why a naive literal-xref scan finds only misaligned "data" hits).

#### 5.8.1 Baud rates & bit timing  [C values · H clock]

A **3-entry BTR (bit-timing) lookup table** sits in the boot config block at file `0x08F062`
(2-byte-aligned, immediately before the default-IP word `192.168.1.1` = `0x0101A8C0` @ `0x08F06E`).
Decoding each word as an STM32 `CAN_BTR` (`BRP[9:0]=psc−1`, `TS1[19:16]=BS1−1`, `TS2[22:20]=BS2−1`,
`SJW[25:24]=SJW−1`) yields **exactly {125, 250, 500} kbit/s only when APB1 = 42 MHz**:

| BTR word | psc | BS1 | BS2 | tq/bit | baud @ 42 MHz | sample point |
|---|---|---|---|---|---|---|
| `0x002B0014` | 21 | 12 | 3 | 16 | **125 kbit/s** | 81.25 % |
| `0x00050014` | 21 | 6 | 1 | 8 | **250 kbit/s** | 87.5 % |
| `0x00270006` | 7 | 8 | 3 | 12 | **500 kbit/s** | 75 % |

- ⇒ **APB1 = 42 MHz ⇒ SYSCLK = 168 MHz** (APB1 = SYSCLK/4). **[H, strong]** — corroborated by
  `FLASH_ACR = 0x705` (5 wait-states + I/D-cache + prefetch) @ `0x67712`, the correct setting for
  168 MHz @ 3.3 V. RCC PLL registers not yet read directly.
- CAN init **indexes this table by a baud selector** (range 1–4, **default 3 → 500 kbit/s**). Menu
  strings **`CANBAUD1`** / **`CANBAUD2`** (`0x02EC2E` / `0x02EC3E`) make each bus's rate
  user-configurable. **CHAdeMO = 500 k, GB/T = 250 k** (standard). The config block is copied to RAM at
  boot (no live flash pointer found).
- **CAN1/CAN2 → CHAdeMO/GB/T assignment still open** (needs the GPIO/pin map, §8.4).

#### 5.8.2 CAN controller init  [C]

Init routine @ `0x67854` (both controllers, HAL-style):
- `MCR = 0x4D` — INRQ (enter init), TXFP, RFLM (RX-FIFO locked), NART (no auto-retransmit), ABOM (auto bus-off recovery).
- `IER = 0x8003` — TX-mailbox-empty + FIFO0-message-pending + sleep interrupts.
- Filters: `FMR` `0xE01→0xE00` (**CAN2SB = 14**, CAN2 filters start at bank 14); `FM1R = 0` (mask mode),
  `FS1R = 0x0FFFFFFF` (32-bit scale), `FFA1R = 0` (all → FIFO0), `FA1R = 0x4001` (**banks 0 & 14 active**).
  Bank 0 regs @ `+0x240` (CAN1), bank 14 @ `+0x2B0` (CAN2). Init leaves a **placeholder filter (ID=0)**
  that the protocol layer reconfigures with the real acceptance IDs/masks.

#### 5.8.3 GB/T 27930 — J1939 identifiers  [C]

29-bit J1939: `priority[28:26] | PGN[25:8] | SA[7:0]`. All GB/T PGNs are PDU1 (PF < 0xF0) ⇒
`PGN = PF<<8`, PS = destination. **Charger (this adapter) SA = `0x56`; vehicle BMS SA = `0xF4`.**
IDs are stored **2-byte-aligned** in flash. The **RX dispatch table** (BMS→charger) starts @ `0x01BF96`
(the preceding instruction `b #0x803BFBA` @ `0x01BF94` branches *over* it, confirming it is data).

**BMS → charger (RX), PS=`0x56`, SA=`0xF4`:**

| msg | 29-bit ID | PGN | file off |
|---|---|---|---|
| BRO (BMS ready) | `0x100956F4` | `0x0900` | `0x01BF96` |
| BCL (demand V/I) | `0x181056F4` | `0x1000` | `0x01BF9A` |
| BSM (status) | `0x181356F4` | `0x1300` | `0x01BF9E` |
| BST (stop) | `0x101956F4` | `0x1900` | `0x01BFA2` |
| BSD (statistics) | `0x181C56F4` | `0x1C00` | `0x01BFA6` |
| BEM (error) | `0x081E56F4` | `0x1E00` (prio 2) | `0x01BFAA` |
| BHM (handshake) | `0x182756F4` | `0x2700` | `0x01BFAE` |
| TP.CM (BMS→chg) | `0x1CEC56F4` | `0xEC00` | `0x01BB92` |
| TP.DT (BMS→chg) | `0x1CEB56F4` | `0xEB00` | `0x01BB96` |

**charger → BMS (TX), PS=`0xF4`, SA=`0x56`:**

| msg | 29-bit ID | PGN | file off |
|---|---|---|---|
| CRM (recognition) | `0x1801F456` | `0x0100` | `0x01C4DA` |
| CML (max limits) | `0x1808F456` | `0x0800` | `0x01C4E2` |
| CCS (charging status) | `0x1812F456` | `0x1200` | `0x01C4EE` |
| CSD (statistics) | `0x181DF456` | `0x1D00` | `0x01C8FA` |
| TP.CM (chg→BMS) | `0x1CECF456` | `0xEC00` | `0x01A4E6`, `0x02E55E` |

**Multi-packet:** BRM/BCP (>8 B) use J1939 **TP.CM (`0xEC00`) / TP.DT (`0xEB00`)** — both directions'
TP.CM/TP.DT IDs are present.

**Built at runtime from PGNs (not literal constants) [H/spec]:** CHM `0x1826F456` (`0x2600`), CTS
`0x1807F456` (`0x0700`), CRO `0x1809F456` (`0x0900`), CST `0x181AF456` (`0x1A00`), CEM `0x181EF456`
(`0x1E00`), BRM `0x1C0256F4` (`0x0200`), BCP `0x1C0656F4` (`0x0600`), BCS `0x181156F4` (`0x1100`),
TP.DT_chg `0x1CEBF456`. All are named in the debug strings (§5.2); their IDs follow the standard GB/T
PGN map + the confirmed SA/PS scheme.

#### 5.8.4 CHAdeMO identifiers  [C from strings · fixed by spec]

CHAdeMO uses **fixed 11-bit IDs** (no addressing). Confirmed used via debug strings / field names:

| dir | ID | msg | notes |
|---|---|---|---|
| RX (veh→chg) | `0x100` | H100 | vehicle status / fault |
| RX | `0x101` | H101 | vehicle charging-enable / contactor |
| RX | `0x102` | H102 | **ChargingCurrentRequest**, VehicleChargingEnabled, VehicleStatus, fault bits; "102.4/102.5" = byte 4/5 |
| TX (chg→veh) | `0x108` | H108 | charger status / available V/I |
| TX | `0x109` | H109 | charger output / contactor state |
| v2.0 | `0x110/0x111/0x112` | H110/H111/H112 | dynamic-control / high-power |
| CBMS | `[103]/[104]/[105]/[301]` | — | vendor "CBMS" (CHAdeMO-BMS) message-set indices |

#### 5.8.5 Protocol timeouts & timebase  [C values · H tick period]

**Timeout durations (from debug strings — actionable, in seconds):**
- **CHAdeMO:** per-message RX watchdog **1 s** (H100/H101/H102 each); whole-CAN-bus loss **6 s**;
  wait for vehicle-charging-enable **8 s** ("From (d1)=ON"); wait for EV contactor / current-request
  **4 s** ("after Switch(d2)=ON").
- **GB/T:** BRM recognition **5 s**; BEM/CEM per-message `Over_Time_Rx`.
- **CBMS:** per-message `[101]…[105]/[301]` timeouts + heartbeat + `EVCC_CATL_BMS_Msg_MaxErrTime`.

**Delay / timebase machinery [C structure]:**
- Busy-delay @ `0x67D32` reads **TIM2_CNT** (`0x40000000+0x24`), extends the 16-bit counter across
  overflow (+`0x10000`), and waits `(arg+5)/10` ticks.
- Core delay @ `0x67D82` = `arg × 1000` busy-units, chunked at 256 000 (`0x3E800`), feeding **IWDG**
  (`0xAAAA`) each chunk; wrappers scale ×100 (`0x67DB0`, `0x6951A`) or ×10 (`0x695F6`, chunk 50 000).
- **Inference [H]:** busy-unit ≈ 1 µs ⇒ TIM2 tick ≈ 10 µs (100 kHz). Exact **TIM2 prescaler / RTOS tick
  period not yet confirmed** (the timer @ `0x6847A` with PSC=83/ARR=1110 is a ~1.111 ms PWM, *not* the
  free-running TIM2 timebase). The numeric tick-constants behind the second-valued timeouts remain to be
  extracted from the state machines.

### 5.9 CCS2 handshake — how the adapter introduces itself (EVCC)  [C unless noted]

Traced end-to-end in code (`hs1.py … hs14.py`, §7). Toward the CCS2 charger the adapter is purely an
**EVCC** (the "EV" side); its identity is its **6-byte PLC MAC**, offered through a **dual
DIN 70121 + ISO 15118-2** protocol proposal. The introduction runs SLAC → SDP → appHandshake →
SessionSetup:

**1. SLAC (ISO 15118-3) — link-level identity.** After CP B→C and the BCB toggle:
`CM_SLAC_PARM.REQ → CM_START_ATTEN_CHAR.IND → CM_ATTEN_CHAR.RSP → CM_SLAC_MATCH.REQ → SET_KEY.REQ`
(NMK/NID for the matched AVLN). The `CM_SLAC_PARM_REQ` builder (`0x001D36`) copies the **6-byte EV
MAC** from a global SLAC struct (`[r5+6]`) into the EVHost-MAC field (`[r5+0x18]`) and appends a
4-byte **RunID** (`[r4+0x24]`); `CM_SLAC_MATCH_REQ` (`0x07EB8A`) logs the same MAC.

**2. SDP — SECC discovery (UDP).** Client @ `0x000A50`: destination port **15118**
(`movw sb,#0x3b0e`), V2GTP payload type **0x9000**. The request payload is 2 bytes
**{security, transport}**: security = **`0x10` (TLS) or `0x00` (no TLS)**, selected by a mode flag
@ `0x000900` (`tst r0,#0xff` → `0x10`/`0x00`) and stored `[r4+0x22]`; transport = TCP.
**500 ms** per attempt (`0x1f4`), **50 retries** (`0x32`). The SECC's offered security is checked
(`0x10`/`0x30`); `"NO TLS"` is logged and TLS (mbedTLS) is used for ISO 15118 PnC — cf. the error
`"EVSE only supports PnC, but no TLS!"`.

**3. appHandshake — `supportedAppProtocolReq` (the formal introduction).** Encoder @ **`0x013F50`**,
V2GTP payload type **`0x8001`** (EXI V2G). It proposes **two** protocols (`[base+0x244]=2`), both
**v2.0** (`r6=2` major, `r7=0` minor):

| # | ProtocolNamespace | Major/Minor | SchemaID | Priority |
|---|---|---|---|---|
| 0 | `urn:din:70121:2012:MsgDef` | 2 / 0 | **1** | **1** |
| 1 | `urn:iso:15118:2:2013:MsgDef` | 2 / 0 | **2** | **2** |

The SECC selects one — debug confirms the mapping (`"#SchemaID == 1,SECC has selected DIN70121!"` /
`"#SchemaID == 2,SECC has selected ISO15118!"`) and the matching DIN/ISO state machine runs.
**DIN is offered as preferred (priority 1), ISO 15118-2 as fallback (priority 2).**

**4. `SessionSetupReq` — EVCCID.** ISO builder @ `0x0145AE`: thunk `0x080890AE` returns the global
EVCC struct; **EVCCID length = 6** (`[r4+0x1408]`); **6 bytes** copied into `[r4+0x1400..0x1405]`
and EXI-encoded. Those 6 bytes are the **same MAC** used in SLAC and printed by `MAC:%02x-…`
(`0x00238C` calls the same thunk). The DIN path shares the SessionSetup encoder (`bl 0x8033EA6`).

**MAC source [H]:** the value is **runtime, not a fixed constant** — held in the global EVCC/SLAC
struct and populated from the **QCA7005 modem** (its PIB MAC). No hardcoded OUI and no
STM32-UID-derived MAC found (`0x1FFF7A10` etc. unreferenced). The exact SPI MAC-read MME is not yet
traced, nor is the SDP security-flag trigger (DIN-vs-ISO / cert availability) — both §8.8.

> **Method note:** strings/peripherals in this image are referenced **PC-relative (ADR T1/T3, LDR
> literal T1/T2)** into inline rodata tables — *not* movw/movt immediates. LDR-literal T2's U-bit is
> **bit 7** (mask `0xFF7F`). `analyze27/34.py` decoded T2 correctly but omitted LDR T1/ADR; `hs3–hs13`
> initially used an inverted mask (`0xFB7F`, U=bit10) that mirrored/dropped forward pool loads —
> **fixed** (`1d26100`; `hs1/hs2` were always correct). A buggy-vs-fixed re-run of all nine scripts
> gave byte-identical output, so the §5.9 conclusions are unaffected (they rest on disassembly + movw
> + ADR). Reference scanner: `corrected_xref.py` (§7).

### 5.10 USB log stick — firmware-match proof & device provenance  [C unless noted]

**Files the device writes to the stick** (observed on the user's unit after boot + charging sessions,
2026-11-18; FAT stick, label `0013-AF1F` — label irrelevant, §5.6):

- `EVCC_<MAC>_INFO.TXT` — nameplate: `HW :1.0`, `SW :02.01.C009[250303]`, `SER:202406180463`,
  `RTC:83501`. Templates f+0x02feee…0x02ff3e (`EVCC_%s_INFO.TXT`, `HW :%u.%u`,
  `SW :%c%c%c%c%c.%c%c%c%c[%02x%02x%02x]`, `SER:`, `RTC:%u`). Serial reads as date-code
  **2024-06-18, unit #0463**; `[250303]` = build date, matches the header (§2.2).
- `EVCC_<MAC>_LOGS.BIN` — 128 KB log export (`EVCC_%s_LOGS.BIN`, f+0x03003e).
- `<UPG>_<MAC>.LST` — update-result marker, observed content `OK` (`%s_%s.LST`, f+0x02ff4f; §5.6).
- `<MAC>` = `9CF6DD923FBF` = the unit's PLC MAC = EVCCID (§5.9).

**LOGS.BIN format [C, empirical — `analyze37.py` / `analyze40.py`]:** records `u32 ts | u16 len | u8 type |
u8 ck | payload[len]`; type 4 = NUL-terminated text line, type 0/1 = raw Ethernet frame (HomePlug
`0x88E1`, variable length, 49–491 B observed); **type 2/3 = DIN70121 V2G EXI** (V2GTP `01 fe 80 01` +
u32 len + EXI body; t3 = EVCC→EVSE req, t2 = EVSE→EVCC res), **type 5 = EXI shutdown / SessionStop**
(4-byte prefix + V2GTP), **type 6 = 512 B CHAdeMO CAN blocks** (16-byte sub-records
`u32 ts_ms | u32 idfield | 8B data`, `idfield = 0x1fff{chan}{msgnum}`, CAN ID = `0x100+msgnum`,
`chan` ∈ {`f9`,`fa`,`ff`} = direction/bus). The record-level `ts` is the **same seconds counter** as the
`at N` in text lines (≈ `INFO.TXT RTC`), *not* milliseconds despite the parser label; the CAN
sub-record `ts` is session-relative ms. Ring buffer in **4 KB flash pages** separated by erased `0xFF`
gaps; spans multiple boots **and firmware versions**. `ck` is not payload sum/xor/any common CRC8
(unresolved; immaterial).

**Export mechanism [C — code + observed]:** the `usbdisk` export (f+0x02fd62) builds
`EVCC_%s_LOGS.BIN`, `f_open`s it, then writer `0x080505d2` **walks the persistent flash page-chain
live**: get-first-page `0x0805053c` reads the **head page index** from a log-control struct, follows
next-page `0x080508dc`, validates each page's **128-byte header** (`0x080889de`), and writes each
valid **4 KB page** to the file (walk cap `0xdc` = 220 pages). So the dump = **all retained history
(previous boots, even previous firmware versions) + the current run up to the export instant** — not
a RAM snapshot of running state, and not frozen at the last boot. Evidence: C002 records survive the
C009 app update (the update writes sectors 5–9, leaving the log region untouched); the last record
`DEEP SLEEP[0] at 83488` sits only ~13 s before `INFO.TXT RTC:83501` (written at export). Bounded
page-chain ring (exported window 128 KB = 32 pages); oldest pages are recycled once full. Practical
upshot: a log pulled after a charge session **does** capture that session — no reboot needed first.

**Proof the device runs THIS image (`analyze39.py`):** of **147 distinct text lines, 105 specifically
match C009** — **12 verbatim literals** (`system init` f+0x02f686, `Passive reset!!!` f+0x030e4e,
`EVController4.EVEmergencyShutDown==1,should goto bms_shutdown` f+0x018966, `#SLAC: Matching failed`
f+0x001c62, …) + **93 rendered format templates** (`UPGRADE:[%u]%c…20%02X-…` f+0x030d72,
`MAC:%02x-…` f+0x002646, `EVCC%u.%u[…]` f+0x002604, `LINKED_EVSE[…] %udB,T:%u` f+0x0025c2,
`CP DUTY is '%c'[…],PP=%u,KEY_LOCK=%u`, `RESET[%u] at %u`, `DEEP SLEEP[%u] at %u`, CHAdeMO stm
messages). **Shared unique misspellings** are the forensic clincher: `authoried` (fw ×12 / log ×5),
`swithc` (×4/×5), `GET_AD_CPD` (×2/×5), `SET_CSS2`. Generic `%s%s` logger-wrapper matches are
excluded from the count (they match anything).

**The log captured the C002→C009 upgrade itself:** `EVCC1.0[02.01.C002]` sessions →
`UPGRADE:[594112]02.01.C009 2025-03-03 09:39:39` → `EVCC1.0[02.01.C009]`. The **42 non-matching lines
are pre-upgrade C002 wording** — lowercase `dlink signal=0` / `Wait for dlink signal->0` /
`MATCHED D_LINK CLOSED BY APP`, `Power up`, `DEEP SLEEP at N` (no bracket), `LINKED_EVSE_…`
(underscores), `CP DUTY is not 5%[…]`, old `17case`/`18 case` CHAdeMO text, `V2G TCP CONNECTED` —
plus the **modem runtime version** `EVCC[01.00.T008]` (QCA7005 fw reported at boot, not an app
string). Each C002-specific core was verified **absent from C009 while its C009 replacement is
present** (`D_LINK` ×19, `system init`, `DEEP SLEEP[%u] at %u`, bracketed `LINKED_EVSE`,
`p->ress_vol`-extended 17/18-case). **Conclusion: same software, version delta — not a different
device.**

**Runtime corroboration of §5.2/§5.8/§5.9:** full CCS2→CHAdeMO sessions logged — DIN70121 selected
(`SchemaID == 1`), SLAC matched EVSE `DC:44:27:1F:30:79` / `DC:44:27:1F:00:10` (28–31 dB), CHAdeMO
H102 exchange (`EV MaximumBatteryVoltage[435]`, `EV TargetBatteryVoltage[410]`, EVSE
`AvailableOutputVoltage[464]` / `50 A`), cable-check / precharge / relay states, ending in
vehicle-side `EVEmergencyShutDown==1` + `H102.BatteryVoltageDeviationError` /
`ChargingSystemError = GBT_STATE_OCCURRENCE`.

**Post-charge dump — the just-finished session IS captured, and it aborts (`analyze40.py`):** a second
dump pulled after a real charge (device powered off post-charge, stick inserted → `RESET[0] at 83500` +
`UPGRADE:[594112]C009` updater check, export at `RTC:83711`) **contains that session**. A text-line diff
misses it — every charge attempt logs identical wording — so sessions must be keyed by the **EXI
SessionID** embedded after the `80 9a 01/02` header: the new session is `0x1091f536` (ts 83400) vs the
previous dump's last `0x10910256` (ts 83246), corroborated by distinct `GET_AD_CPD` (1.751 vs 1.743) and
cable-check voltage (51 V vs 253 V). This empirically confirms the export mechanism above (current run
up to the export instant). **The charge again ends at `charging_tm[0]minutes`** — the raw CAN/EXI show
why: car H100 max battery 435 V / H102 battery 410 V (`9a 01`); adapter-as-EVSE H108 advertises 464 V /
50 A, threshold 435 V (`d0 01`/`32`/`b3 01`); after switch-K + cable check the **output voltage is only
51 V** (prior session 253 V) and the car requests just **2 A** (H102 byte0=`02`), then H102 error byte5
flips `0x80→0x88`: `BatteryVoltageDeviationError` flood → `ChargingSystemError` →
`EVEmergencyShutDown==1` → 16× t5 PowerDelivery-stop / SessionStop exchanges → close A+/unlock.
**Root cause: the EVSE output never ramps to the car's battery voltage (≈51 V vs 410 V), so the CHAdeMO
EV flags a battery-voltage deviation and emergency-stops within seconds — every logged session aborts
at 0 minutes.** No new protocol behavior vs §5.2/§5.8; the value is the raw-frame confirmation plus the
lower-voltage data point. (H102 layout confirmed from raw frames: byte0 = charging-current request,
byte1–2 = battery voltage, byte5 = error flags.)

**Device provenance [C strings · H maker]:** vendor **Orientrise disavows this unit as a clone**
(user contact, 2026-11-18). The firmware's own nameplate carries a different mark —
`$$KM-CCS2CHAdeMO-1` / `$$CCS2GBT` (§2.2) — plus an ID block at f+0x090df0:
`F$K$N$T$2005$TY$KM-CCS2CHAdeMO-1` and `F$K$N$T$2005$VR$CAMA000000002.01…C009`, followed by a
function-pointer table. BMS/AC symbols are **CATL/CAMA-specific** (`EVCC_CATL_CHARGE_FORBID`,
`EVCC_CATL_BMS_Msg_MaxErrTime`, `EV_CAMA_ALLOW_AC_START/STOP/PERMIT`). Modem confirmed **QCA7005**,
fw string `MAC-QCA7005-1.1.0.727-02-20130826-FINAL` (f+0x002596). **The MAC OUI is not a maker ID:**
`9C:F6:DD` (unit) and `DC:44:27` (EVSE) both register to **IEEE Registration Authority** in the
authoritative IEEE `oui.txt` — reference/default PIB MACs (a third-party "Annapurna Labs" hit is
stale/wrong). Maker identity beyond the **"KM"** mark unresolved → §8.9.

### 5.11 C013 vs C009 — reseller update delta  [C strings · H behavior]

A newer **C013** build (reseller-supplied 2026-11-18; `MAIN_CCS2CHADEMO_1[02.01.C013]…rar`,
`analyze41.py`) vs the installed **C009** (from OEM Orientrise): build **2026-03-27 09:33:27** (vs
2025-03-03), **+4424 B** (599564 vs 595140), same `KM-CCS2CHAdeMO-1` / `CCS2GBT` / `CAMA…2.01` model.
Outer XOR key `25 A8` (self-described, §2.1); prefix footer `0x2208 / 9 / 0x0BA8` (§4.1). 2648 common
strings, 96 added / 76 removed — but most "adds/removes" are offset-shift artifacts; **phrase counts**
give the real deltas.

**Genuinely new in C013 (absent in C009):** H108/H109 vehicle-enable timeout **8 s → 18 s**; precharge
wait-to-`TargetBatteryVoltage` (`Precharge,wait out[%lu]reach ress_vol…`); **inner-contactor close
wait**; configurable d2 contactor timeout (`8s (or %dseconds)`); explicit **CAN 15 s H100/H101/H102
timeout**; **CurrentDemand periodic current limiting** (`every n minute adjusts current limintation`,
`setpara_maxevsecurrent`) + telemetry `chaEVrCur/Vol, fwdCur/Vol, evseOutCur/Vol, maxCur, maxP`;
16-case now logs `TargetBatteryVoltage`; cable-check switch `SET_CSS2` → `SET_CSS2(D2)`.

**Already in C009 (not new):** states 31/32/50, `CurrentDemand phase` base, `bms_error_stop`,
`get_evcc_hw_fault`, `notify_normal_shutdown`, `phase_cnt`, `EVEmergencyShutDown` handling — so C013 is
an **incremental refinement, not a rewrite** (the ~481 KB "changed" byte region is mostly code shifted
by ~2.5 KB of insertions).

**Charging behaviour — the voltage-mismatch abort is fixed (confirmed on post-update charge logs).**
The §5.10 failure is the CCS2↔CHAdeMO *engagement* mismatch (prior art: `osexpert/ccs32clara-chademo`,
§8.2b): a CCS2 EVSE is a current source, but a CHAdeMO car expects the charger to ramp/regulate its
output to the battery voltage *before* the contactors mate, then deliver a fast current ramp. **C009**
closed the precharge relay as soon as output ≈ measured residual voltage (`17case … Precharge voltage
OK … outvol≈ress_vol`) without waiting for the EVSE to reach target, so output never regulated up to the
battery: the car held itself to ~1–2 A and raised H102 `VoltageDeviation`+`CurrentDeviation` →
`ChargingSystemError` → `EVEmergencyShutDown` (0-min abort) or a brief trickle then EVSE shutdown.
**C013** bridges the engagement: state 17 now **stalls precharge** (`Precharge,wait out[%lu]reach
ress_vol…`) until the EVSE output actually ramps to the car-side residual/battery voltage, then sequences
`wait CLOSE inner contactor` → PowerDelivery-finish; the H108/H109 enable timeout 8→18 s and CAN 15 s
timeout give the EVSE time to ramp, and CurrentDemand `setpara_maxevsecurrent` periodically raises the
current ceiling. Post-update logs show the EVSE output ramping to battery voltage before relay close, the
car's current request ramping normally (tens of amps, not 1–2 A), EVSE voltage tracking the rising battery
toward target, and **sustained charging at real power with no deviation flood / emergency abort**. A
precharge-timeout path remains (`PreChargeRes t>=…tout`): if the EVSE never answers PreCharge (output
stuck near 0 V) C013 still aborts that attempt, but recovers on retry. C013 also bumps the boot banner
`EVCC1.0[…]` → **`EVCC2.9[02.01.C013]`** (the `2.9` is the `HW:` version now in INFO.TXT); `analyze42.py`
matches `EVCCx.y` accordingly.

**Caution:** clone unit; the fixed **prefix stream-cipher key** + any version/hardware check in the
undumped bootloader are the real compatibility gates (§5.6) — dump `boot.bin` via `acq/` (§5.7) before
flashing.

### 5.12 Bootloader → app entry contract (service-firmware basis)  [C structure · H launch details]

Traced from the clear code at file `0x400` (`analyze45/46`, capstone) on **both** C009 and C013:

- **File `0x400` is NOT code — it is a 10-byte entry header.** The first halfword `0xF866` is an
  invalid Thumb-2 start. Layout:
  - `0x400–0x403` (4 B): **per-build value** — C009 `66 F8 18 4D` (`0x4D18F866`), C013 `5C 32 70 4D`
    (`0x4D70325C`). Not a CRC of any region — standard CRC32/CRC16/Adler32/XOR/sum (`analyze47/49/50`)
    **and** packed-CRC16-pair / MODBUS-poly-CRC32 / subregion-CRC hypotheses (`analyze54`) all fail.
    **[H]** a per-image **IV/nonce** for the prefix stream cipher (the prefix ciphertext differs in
    **913/914 bytes** between revisions ⇒ per-image keystream, not a fixed one). Kept stock (§5.13).
  - `0x404–0x409` (6 B): **constant** `02 20 09 00 02 08` across revisions (u16s `0x2002 / 0x0009 /
    0x0802` — plausibly SP-high / count / base-high metadata). **[H]**
- **Reset_Handler is at file `0x40A` (`0x0802040A`)** — the reset vector in the decrypted prefix
  targets it (it cannot target `0x400`, which is not executable). Sequence:
  `cpsid i; cpsid f; ldr r0,[pc,#0x3c]; ldr r0,[r0]; msr MSP,r0; msr PSP,r0; bl SystemInit;`
  zero-fill `.bss` (SRAM `0xC000` words @`0x20000000`, CCM `0x4000` words @`0x10000000` — §3.3);
  `ldr r0,[pc,#0xc]; bx r0`. ARM **scatter-load / relocation** helpers follow at `0x45E`.
- **Two literal-pool words are bootloader-filled placeholders** (identical in C009 & C013, and not
  valid addresses as stored): `0x44C` = `0x0000BBC3` (MSP source, double-dereferenced) and `0x450` =
  `0x00550802` (the `bx` entry target). **[H, strong]** the bootloader patches these at install (e.g.
  `0x44C`→`0x08020000` so the app re-reads `vector[0]`=SP; `0x450`→the real entry), or the app reads SP
  from the bootloader via the `0x00000000`→flash alias. Either way **the bootloader modifies the app
  image at fixed offsets `0x44C`/`0x450`** — a service firmware must keep a compatible startup stub there.
- **Integrity fields cracked (§5.13):** footer u16 `0x3FE` = CRC16/MODBUS(`dec[0x3EA:0x3FE]`);
  last-4-bytes trailer = `00 00` key-echo + u16LE CRC16/MODBUS(`dec[2:n−2]`) (C009 `00 00 9F 00`,
  C013 `00 00 D6 10`). Both recomputable ⇒ a rewritten/extended app can be re-sealed. The
  first-4-bytes `0x400` remain a per-image IV/nonce (not a CRC). Whether the **bootloader** also
  checks the code at boot (beyond these CRCs) is the remaining question → §8.2b / §5.13.

**Service-firmware consequence (non-invasive bootloader dump):** the encrypted prefix + footer can be
**reused verbatim** from a stock UPG — the bootloader then decrypts the *stock* vector table (reset →
file `0x40A`) and applies its usual checks/patching. Keeping file `0x000–0x45E` (header + prefix +
footer + entry header + startup stub) byte-for-byte stock and replacing only the application code the
stub jumps to is the lowest-risk way to get a **vendor-bootable** service image that reads
`0x08000000–0x08020000` out to USB and can re-flash a stock `MAIN_…UPG` to back out. **Implemented:**
`make_service_upg.py` (§5.13) reuses the stock prefix/entry verbatim, applies app patches / appends a
dump cave, and re-seals both MODBUS CRCs + the length field — `SERVICE.UPG` round-trips byte-identical
to stock (safe recovery image); `SERVICE_DUMP.UPG` adds a one-shot bootloader-dump cave on the in-place
`f_close` anchor (§5.13f). **Bench-confirmed working (§5.13h):** it dumped the bootloader to USB
(`acq/dump/boot.bin`, §5.14) — the runtime model (FatFs in place, scatterload-derived free RAM) is
established (§5.13b) and the original non-invasive acquisition goal is met. The `acq/` SWD kit (§5.7)
remains an alternative dump path. Remaining interpretation tasks on the dump: the exact patched entry
address (`0x450`), the prefix-cipher key, and any boot-time code check (§5.14).

### 5.13 UPG integrity cracked, encoded-overlay pack, and the service-UPG builder  [C fields · C runtime model · C cave]

**(a) Integrity fields = CRC16/MODBUS (recomputable).** The trailing bytes are memory-integrity
*metadata*, not a secret and not an app-enforced gate (`analyze51/52/54`, confirmed C009 **and** C013):

| field | offset | value / coverage |
|---|---|---|
| length | u32LE `0x3F2` | `filesize − 0x404` (app-code byte count) |
| footer CRC | u16LE `0x3FE` | **CRC16/MODBUS**(`dec[0x3EA:0x3FE]`) — over the 20-byte footer itself |
| trailer | `dec[n−4:n]` | `00 00` (key echo) + u16LE **CRC16/MODBUS**(`dec[2:n−2]`) — over the whole body |
| first4 | u32 `0x400` | per-image **IV/nonce**, *no* CRC relation — kept stock |

MODBUS = poly `0x8005` reflected (`0xA001`), init `0xFFFF`, refin/refout true, xorout 0. The earlier
"no standard CRC" hunts (`analyze44/47/49/50`) missed it by testing wrong ranges/inits; a **differential
CRC attack** (`analyze52`: for same-length messages `CRC(m1)⊕CRC(m2)` cancels init/xorout) pinned the
poly, then `analyze54` verified both fields explicitly. **The app updater does NOT verify a whole-image
checksum** — there is no CRC32 routine in the app; the writer only does per-word flash read-back (§5.6).
So the CRCs are recomputable and any boot-time whole-image check would be **bootloader-side**.

**(b) Encoded-overlay: literal pools are +2-byte packed (mild anti-RE).** The app's literal pools are
**halfword-swapped and shifted +2 bytes** relative to where the LDR-literals point (`analyze63/64`):
- Flash writer: unlock keys `0x45670123`/`0xCDEF89AB` sit at file `0x9118E`/`0x91192`, but the
  LDR-literals reference `0x9118C`/`0x91190`; FLASH base `0x40023C00` is at `0x9118A` while the code
  loads `0x91188`.
- FatFs pools likewise: stored `0xBCB82001` → swap16 → `0x2001BCB8` (a valid SRAM address).

⇒ the flash writer (and pool-bearing code) is **not directly executable from the stored bytes**; the
pools are fixed up at install. The `usbdisk` overlay (`0x02FF00–0x030300`) is separately **RAM-relocated**
(its 32 BLs hit zero FatFs targets; its strings have zero static xrefs — `analyze57/58`). This is a light
pack, not crypto: it defeats naive static constant-xref scanning, nothing more.

**Bootloader-decode model (confirmed).** The bootloader **unobfuscates the image on first boot after an
upgrade** — XOR-decode + storage-pool decode written back to flash — then hands off to the app, which runs
normally on subsequent boots. Evidence: the device log shows a `RESET`/system-init pass after each
`UPGRADE` (h), and the **scatterload relocates DATA ONLY** (no code region; `analyze68`), so app code —
**including FatFs — executes in place at `BASE+file_offset`** from the decoded flash. Only the flash writer
is SRAM-copied (it erases its own bank; STM32F4 stalls instruction fetch from a bank during erase/program).
The 595 KB image exceeds the 256 KB RAM, so whole-image RAM execution is impossible — in-place flash
execution is forced.

**Scatterload region table → free RAM (`analyze68`, file `0x48A`, adr@`0x45E`).** Four DATA regions only:

| region | load (flash) | exec (RAM) | size | init |
|---|---|---|---|---|
| R0 `.data` | `0x080B0A44` | `0x20000000` | `0x3B8` | copy |
| R1 `.data` | `0x080B0DFC` | `0x200003B8` | `0x78C` | decompress |
| R2 `.bss` | `0x080B10C0` | `0x20000B44` | `0x241D4` (147 924) | zero |
| R3 CCM `.bss` | — | `0x10000000` | `0xFE2C` (65 068) | zero |

⇒ `.bss` ends **`0x20024D18`**; main SRAM is 192 KB (`0x20000000–0x2002FFFF`), MSP stack at top
`0x20030000`. The **free SRAM gap `0x20024D18..0x20030000` (45 800 B)** is usable scratch (above
`.bss`/heap, below the ISR/MSP stack); the cave places `FIL/BW/FLAG` at `0x2002E000` (~37 KB above `.bss`
end, 8 KB below stack top). No code region is relocated ⇒ the FatFs anchors in (d) are valid **in-place**
hook targets.

**(c) Flash-writer signature (SRAM-executed — *not* a hook anchor).** `flash_write(sector=r0, offset=r1, data=r2, len=r3)`;
entry at file `0x910AC` (runtime `0x080B10AC`), prologue `push.w {r4-r11,lr}` (`E92D 4FF0`), then
`0x910B0 mov r8,r2 / mov r7,r0`. FLASH base `0x40023C00`. App code ends runtime `0x080B14C0`; the
**unused sector-9 tail** file `0x914C0..0xA0000` = **60 224 B** is cave space (no ≥256 B `0xFF`/`0x00`
padding runs exist inside the app itself — `analyze65`).

**(d) FatFs API anchors (NORMAL code, runtime = `BASE+offset`).** Identified via `f_mkfs`→`disk_write`
callers and `validate` callers (`analyze60–67`):

| function | file offset | note |
|---|---|---|
| `f_open` | `0x0363E0` | `FA_*` mode `&0x3f`, create tst `#0x1c`, FIL init |
| `f_read` | `0x036584` | tests `FA_READ` bit0 |
| `f_write` | `0x0366C8` | tests `FA_WRITE` bit1 |
| `f_sync` | `0x03685A` | flush dirty buf + dir-entry **size**/cluster/time, `sync_fs` |
| `f_close` | `0x0368E8` | calls `f_sync` then clears `fp->obj.fs` |
| `f_lseek` | `0x035792` | |
| `f_mkfs` | `0x036F20` | |
| `find_volume` / `validate` | `0x0360F2` / `0x036368` | |
| `move_window` | `0x035398` | |
| `disk_read` / `disk_write` / `disk_ioctl` | `0x038ED8` / `0x038F28` / `0x038F80` | |
| low-level read / write | `0x038D48` / `0x038DEE` | |

`FIL` ≈ 552 B (`0x228`): `obj.fs@0`, `obj.id@4`(u16), `obj.attr@6`, `obj.sclust@8`, `obj.objsize@0xC`,
`flag@0x10`, `err@0x11`, `fptr@0x14`, `clust@0x18`, `sect@0x1C`, `dir_sect@0x20`, `dir_ptr@0x24`,
`buf@0x28[512]`. (`0x036A9C` is validate+clear **without** sync — *not* `f_close`; using it would leave a
0-byte file. `0x0358C8` is a dir-traversal helper, `0x036A3C` is `f_open`-like — both ruled out.)

**(e) `make_service_upg.py` — the builder.** Implements (a)–(d): derive key from `raw[0:2]`, XOR-decode,
drop the 4-byte trailer, apply app patches (rejects any offset `<0x40A` to protect the entry shell),
optionally append a cave (pad `0xFF` to the cave offset; reject overlap / beyond `0xA0000−4`), then
re-pack length@`0x3F2`, footer CRC@`0x3FE`, trailer CRC@`n−2`, and re-XOR. Asserts `[0:0x3EA]`
(key/header/prefix) and `[0x400:0x45E]` (entry header + startup) and first4 stay verbatim — the footer
metadata `[0x3EA:0x400]` legitimately changes when the image grows. The prefix ciphertext is kept
verbatim, so its per-image keystream is **not** needed. With no patches it re-emits a **byte-identical**
UPG (`SERVICE.UPG`) — a round-trip proof of the format and a safe, bootable, stock-equivalent recovery
image. `--verify-only` checks any UPG's CRCs.

**(f) `SERVICE_DUMP.UPG` — bootloader-dump cave (in-place `f_close` anchor, bench-confirmed).** `--dump-hook`
patches the **in-place** FatFs `f_close` entry `0x0368E8` → `b.w` cave at file `0x92000` (runtime
`0x080B2000`, unused sector-9 tail). `f_close` runs in place (b), unlike the SRAM-copied flash writer, so
the hook **is** the executed copy. The cave (hand-encoded Thumb, capstone-verified, pool-free
`movw/movt/adr/bl`): `push.w {r0-r12,lr}`; one-shot guard `FLAG==MAGIC` (`0x2002E234`) → `beq fin`;
`f_open(&FIL,"0:/BOOT.BIN",0x0A)` (`FA_CREATE_ALWAYS|FA_WRITE`); on failure `bne fin` (**FLAG stays unset →
retry** if the volume isn't mounted yet); on success arm `FLAG=MAGIC`, `f_write(&FIL,0x08000000,0x20000,&BW)`,
`f_close(&FIL)` (re-enters the hook, sees FLAG set → real close: syncs the 131 072-byte size + releases any
lock slot); **`fin:`** `pop.w {r0-r12,lr}`; re-exec the original `f_close` prologue verbatim
(`push {r3,r4,r5,lr}; mov r4,r0` = `38 b5 04 46`); `b.w f_close+4` (`0x080568EC`) — so **every real close
completes** (stock update/recovery preserved). The shared `fin` epilogue pops each frame exactly once: the
inner `f_close(BOOT.BIN)` returns into `fin`, which then services the outer frame — recursion-safe,
stack-balanced. `FIL=0x2002E000` (0x228 B), `BW=0x2002E230`, `MAGIC=0x2003D00D`. Independent re-verification
(`analyze66`): both MODBUS CRCs, length, key-echo, first4/entry/prefix preservation, cave-in-sector-9, hook
target + resume point, and the full cave sequence all pass.

**(g) Bench-verify gates — all cleared on re-test.** The in-place anchor + scatterload free-RAM (b)
resolved the two defects that killed the first cave (h). The remaining risks were: (1) **bootloader
pool-decode of the hook/cave bytes** — the cave is pool-free (`movw/movt/adr/bl`), so a *selective*
literal-pool decode has nothing to corrupt (a *blanket* halfword-swap of the overlay region could have
damaged the `b.w` hook or cave code); (2) **exact free-RAM safety** — `0x2002E000` is above `.bss` end and
below the MSP stack top (a heap growing up from `.bss` or a deep ISR stack could have collided); (3) **FatFs
re-entrancy** — a second `FIL` opened while the UPG/LOGS file is open (FatFs non-reentrant); (4) **stack
headroom** (~330 B for the pushed frames + FatFs locals). **All four were cleared by the successful bench
re-test (h):** the cave dumped `BOOT.BIN` cleanly with no hardfault and stock recovery still works.
`SERVICE.UPG` (no hook) is safe to flash at any time as a stock-equivalent; the dump variant is
**bench-confirmed working**.

**(h) Bench confirmation (hardware) — format/recovery CLOSED; first cave failed, corrected cave SUCCEEDED.**
The first `SERVICE_DUMP.UPG` (flash-writer anchor) was **accepted by the bootloader** and installed (device
log `UPGRADE:[597112]` = the exact rebuilt length `0x91C78`), and the running service image then
**re-flashed a stock `MAIN_…UPG`** (`UPGRADE:[594112]`) — so the re-sealed CRCs + extended image **boot**,
and the **stock-recovery path works end-to-end**. That first cave produced **no `BOOT.BIN`**, yet the
update ran clean (no hardfault). Two cave defects explain it:
  1. **Invalid scratch RAM** — the cave used `FIL/BW/FLAG = 0x2003Fxxx`, but main SRAM is **192 KB**
     (`0x20000000–0x2002FFFF`, confirmed by the `.bss` zero-fill of `0xC000` words, §3.3); `0x2003F000` is
     **out of range** — any access bus-faults.
  2. **Wrong hook anchor** — the flash writer **executes from SRAM**, not in place: it erases/programs the
     same flash bank it resides in (STM32F4 stalls instruction fetch from a bank during erase/program), so
     it must run from a SRAM copy. The in-flash hook at `0x910AC` is **not the executed copy**.
  A clean update with **no hardfault** means the cave body **never executed** (running it would fault on
  defect 1) ⇒ defect 2 is the primary cause. **Consequence:** a working USB-dump cave needs (a) an
  **in-place** hook anchor and (b) a valid free-RAM region. The corrected cave (f) supplies both without
  SWD: the in-place FatFs `f_close` anchor (the scatterload relocates data only, so FatFs runs in place —
  (b)) and scratch RAM in the scatterload-derived free gap `0x2002E000` (above `.bss` end `0x20024D18`,
  below the MSP stack). **Bench re-test SUCCESS:** the corrected cave produced `BOOT.BIN` of exactly
  `0x20000` B on the USB stick — the bootloader is **acquired non-invasively** (§5.14), closing the
  runtime-model gate (g). The format/recovery gates are **closed**; the original acquisition goal is met.

### 5.14 Bootloader acquired via the dump cave — structure (`acq/dump/boot.bin`)  [C dump · H orchestration]

The corrected `f_close` cave (§5.13f) produced `BOOT.BIN` = exactly `0x20000` B; preserved at
`acq/dump/boot.bin`, triaged by `acq/analyze_boot.py`. **RDP Level 0** (sane Cortex-M vector table),
**plaintext** (not XOR/pool-encoded — the bootloader is the *decoder*, §5.13b). It is small: of the 128 KB
region (sectors 0–4) only sector 0 is densely populated (~10.6 KB non-`0xFF`), sectors 1–3 sparse, sector 4
fully erased; whole-image entropy 0.99 bits/B (mostly erased flash).

**Vector table + reset startup.** `vector[0]` initial SP = `0x20028968`; `vector[1]` reset = `0x08000009`
(handler @ `0x08000008`, code follows the 2-word SP+reset immediately). Reset @ `f+0x8`: `cpsid i/f` →
load SP from `[0x08000000]` → `msr MSP/PSP` → `bl 0x08000246` (clock/init: RCC `0x40023800`, PWR
`0x40007000`) → **zero-fill `0xC000` words = all 192 KB SRAM** (`0x20000000..0x20030000`) → `bx 0x0800003C`
(boot main).

**Own flash writer (~`f+0x2570`).** `push.w {r0-r12,lr}` … `cmp r2,#8`; `FLASH_KEYR` keys
`0x45670123`/`0xCDEF89AB` @ `f+0x2554/0x2558`, FLASH base `0x40023C00`, app base `0x08020000`. Confirms the
bootloader itself programs flash (the install/decode pass of §5.13b).

**Boot→app entrypoint (the original question).** Accessor helpers read the app vector table at
`0x08020000`: `get_app_reset()` = `ldr r0,=0x08020000; ldr r0,[r0,#4]; bx lr` (`f+0x240`, `f+0x1918`) →
app reset vector @ `0x08020004`; `get_app_base()` = `ldr r0,=0x08020000; bx lr` (`f+0x1922`, `f+0x251A`).
A boot-decision/launch cluster @ `f+0x1926` calls update/USB checks (`bl 0x080021D8` etc.), reloads IWDG
(`0x40003000` ← `0xAAAA`), `cpsie if`; `SCB_AIRCR` (`0xE000ED0C`) referenced @ `f+0x18BC`. This corroborates
the app-side entry contract (§5.12): app base `0x08020000`, reset vector @ file `0x40A` ⇒ runtime
`0x0802040A`. **[H]** the exact MSP/VTOR-set + `bx` jump sequence is in this cluster, pending full trace.

**Recovery + UPG components.** XMODEM-1K serial recovery (`"->1K Xmodem"` / `"EXIT XMODEM1K"` @
`f+0xF94/0xFBA`). UPG component name strings `MAINARM` / `BOOTARM` / `ROOTCERTS` / `PRIROOT` @
`f+0x20E4..0x2100` ⇒ the UPG is **multi-component** (app / bootloader / root certs). ID block
`F$K$N$T$2005$VR$CAMA0FDQC000V3.6#` @ `f+0x46C` + `TY$KM-CCS2CHAdeMO-1` @ `f+0x4AC` (matches the app,
§5.10); log strings `RDP:%u`, `FLASH_OPT:%08x`, `USER PRG SADR:0x%08x`, `NO USER PRG`. Peripherals
referenced: RCC, FLASH, USB_OTG_FS (`0x50000000`), CAN1/CAN2, IWDG, PWR.

**Remaining (deeper RE, not yet traced):** exact app-jump sequence; update orchestration (USB MSC read →
XOR/prefix decode → flash write); the **prefix stream-cipher key/routine** (§4.1, the one piece the app
never needed); XMODEM-1K protocol details; UPG component parsing; any boot-time whole-image verify beyond
the CRCs (§5.13a). The dump itself is complete and verified — these are interpretation tasks on
`acq/dump/boot.bin`, no further hardware access required.

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

> **Minimal service firmware — feasibility (2026-11-18, updated with §5.12/§5.13):** a bare-metal
> STM32F427/F429 firmware that **boots + includes the flasher + dumps the bootloader** is buildable from
> §5.6 (the flash-writer algorithm is fully decoded; USBH MSC + FatFs are open in STM32CubeF4). The
> **entry contract is mapped (§5.12)** and the **integrity fields cracked (§5.13):** reset vector → file
> `0x40A`; the encrypted prefix + footer + startup stub (file `0x000–0x45E`) are **reused verbatim** from a
> stock UPG so the bootloader decrypts the stock vector table — **no prefix key needed**; footer + trailer
> are **CRC16/MODBUS**, recomputable, and the app does **not** verify a whole-image checksum.
> `make_service_upg.py` already builds `SERVICE.UPG` (byte-identical stock round-trip, safe) and
> `SERVICE_DUMP.UPG` (bench-confirmed dump cave). The **runtime model is now established (§5.13b):** the
> bootloader decodes the image on first boot after an upgrade and the scatterload relocates **data only**,
> so FatFs runs **in place** and the cave hooks `f_close` with scratch RAM in the scatterload-derived free
> gap. The corrected cave is **bench-CONFIRMED working** (§5.13h): it dumped `BOOT.BIN` (`0x20000` B) to
> USB, acquiring the bootloader non-invasively (`acq/dump/boot.bin`, §5.14) — the original goal. The
> `acq/` read-only SWD kit (§5.7) remains available as an alternative dump path (non-destructive at any RDP
> level; `dump_image` / `stm32flash -r` / `dfu-util -U` at RDP0) but was **not needed**. Open items: deeper
> bootloader RE on the dump (update orchestration, prefix-cipher key, exact app-jump — §5.14), the entry
> address patched into literal `0x450`, and any **boot-time** code check beyond the CRCs.

---

## 7. Artifacts produced (in `re/`)

- `decode_upg.py` — reusable decoder (**auto-derives the self-describing XOR key from `raw[0:2]`**, §2.1;
  + header parse + string dump). Handles any revision (C009 `2B 23`, C013 `25 A8`, …).
- `firmware.bin` — fully decoded image (595 140 B).
- `strings.txt` — 2 724 unique strings ≥6 chars, with offsets.
- `decoded23.bin` — same decoded image (analysis copy).
- `analyze1.py … analyze35.py` — the analysis trail (entropy, autocorr, key recovery, vector/peripheral
  scans; **15–18** = prefix cipher / QCA-blob / link-base; **19–24** = `usbdisk` update module, flash
  writer, sector tables, XOR-key absence, flash-writer call graph; **25–26** = bootloader search /
  vector-table scan — **negative**, no embedded bootloader; **27–35** = CAN deep-dive (§5.8): register
  xrefs, MOVW/MOVT + MOV-imm + LDR-literal immediate decode, GB/T J1939 ID tables, BTR baud decode,
  SysTick/TIM2 timebase scan).
- `analyze28.py` — reusable **capstone Thumb-2 disassembler** for any decoded region
  (`python3 analyze28.py firmware.bin <start_hex> <len_hex> [base_hex]`; needs
  `nix-shell -p python3 python3Packages.capstone`).
- `hs1.py … hs14.py` — **CCS2-handshake trail (§5.9)**: Thumb xref scanner (movw/movt, LDR-literal
  T1/T2, ADR T1/T3) + appHandshake / SessionSetup / SDP / SLAC disassembly. `hs3–hs13` originally had
  an inverted LDR-literal T2 U-bit (bit10 instead of bit7) that dropped forward pool loads — **fixed**
  (`1d26100`); a buggy-vs-fixed re-run confirmed the §5.9 results are unchanged. Run with
  `nix-shell -p python3 python3Packages.capstone --run 'python3 hsN.py firmware.bin'`.
- `corrected_xref.py` / `verify_enc.py` — corrected reference xref scanner (movw/movt + mov-imm +
  LDR T1/T2 correct-U + ADR T1/T3) and the capstone proof that LDR-literal T2 U=bit7 (§5.9 method note).
- `acq/` — **non-destructive bootloader/flash acquisition kit (§5.7, §8.2b)**: read-only, probe-gated SWD
  dump (`swd_dump.sh` / `swd_dump.tcl`, ESP32-S3 CMSIS-DAP + OpenOCD; refuses to dump on RDP1/2), UART
  (`uart_dump.sh`, `stm32flash -r`) / USB-DFU (`dfu_dump.sh`, `dfu-util -U`) system-bootloader fallbacks,
  and `analyze_boot.py` (vector-table sanity → reset disasm → XOR-key / `$$`-magic / `XIE22.00` /
  `FLASH_KEYR` / app-launch hunt). Never unlocks/erases/writes. Tools via `nix-shell` (openocd 0.12.0,
  stm32flash 0.7, dfu-util 0.11). Procedure + safety: `acq/README.md`.
- `analyze37.py … analyze39.py` — **USB log-stick trail (§5.10)**: `analyze37` = `EVCC_<MAC>_LOGS.BIN`
  record parser (multi-segment 4 KB ring buffer; text lines + HomePlug frame/MAC summary),
  `analyze38` = firmware identification-string hunt (`$$KM-…` nameplate, QCA7005 fw string,
  CATL/CAMA symbols, INFO.TXT/UPGRADE templates), `analyze39` = **log↔firmware match proof**
  (verbatim literals + printf-template regex matching + shared-typo fingerprints; `%s%s` catch-alls
  excluded). Run: `nix-shell -p python3 --run 'python3 analyze39.py firmware.bin EVCC_…_LOGS.BIN'`.
- `analyze40.py` — **raw car↔charger decoder (§5.10)**: keys LOGS.BIN EXI records by **SessionID**
  (separates charge attempts that share identical text wording), prints the DIN70121 EXI sequence
  (t2/t3 req/res, t5 shutdown) and decodes the t6 **CHAdeMO CAN** sub-records (H100–H112, both
  directions). Run: `nix-shell -p python3 --run 'python3 analyze40.py EVCC_…_LOGS.BIN'`.
- `analyze41.py` — **firmware revision diff (§5.11)**: C009 vs C013 header / unique-string add-remove /
  common-offset-shift / byte-change-region (flash-sector mapped) / prefix-footer / `F$K$N$T$2005`
  ID-block comparison. Run: `nix-shell -p python3 --run 'python3 analyze41.py firmware.bin decoded_c013.bin'`.
- `analyze42.py` — **ring-buffer epoch/session mapper (§5.10)**: the LOGS.BIN `ts` counter overlaps across
  firmware upgrades, so true chronology is **file-offset (write) order**, not `ts`. Raw-scans version
  banners (`EVCC1.0[02.01.Cxxx]` / `EVCC[01.00.Txxx]`), `UPGRADE:[size]ver date` and `RESET` markers to
  delimit firmware epochs, walks records tagging each with its epoch + SessionID, and prints an event
  timeline (banners / SLAC / SessionSetup / CHAdeMO state milestones / errors) plus per-session offset/ts
  ranges. `--tail OFFSET` dumps a region record-by-record (e.g. the newest firmware-install tail). Use to
  attribute a charge session to the firmware that actually ran it. Run:
  `nix-shell -p python3 --run 'python3 analyze42.py EVCC_…_LOGS.BIN [--tail 0x23000]'`.
- `analyze43.py` — **per-session CAN timeline (§5.10)**: decodes the t6 CHAdeMO H-messages for a single
  SessionID in time order — H100 maxV / H101 / H102 charge status / H108–H109 EV status / H110 EVSE status —
  to expose the cable-check → precharge → charge → shutdown voltage/current/error evolution (the steady-state
  charge itself logs no records, so the bracketing phases carry the evidence). H102 layout: byte0 = current
  request [A], bytes1–2 = battery voltage [V], byte5 = error flags (0x80 VoltageDeviation, 0x08
  CurrentDeviation). Run: `nix-shell -p python3 --run 'python3 analyze43.py EVCC_…_LOGS.BIN <SessionIDhex> [--all]'`.
- `analyze44.py … analyze50.py` — **bootloader→app entry-contract trail (§5.12)**: `analyze44` =
  prefix-footer reinterpretation (u32 length = filesize−0x404, confirmed both revisions) + C009/C013
  prefix-ciphertext compare (913/914 bytes differ ⇒ per-image keystream); `analyze45/46` = capstone
  entry disasm (file `0x400` = 10-byte header, Reset_Handler at `0x40A`, MSP/PSP + `.bss` zero-fill +
  scatter-load; `46` skips the `msr` halfwords capstone rejects to reveal true alignment);
  `analyze47/49/50` = integrity-field hunts (first-4-bytes `0x400`, last-4 trailer, footer u16 `0x3FE`)
  across CRC16/CRC32/Adler32/XOR/sum, decoded+raw, code+prefix, sector-padded — **no standard match**;
  `analyze48` = UPG-string xref scan (update strings are reached via `.rodata` pointer tables, so direct
  ADR xrefs are 0 — use `analyze19–24` for the update module). Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze46.py firmware.bin'`.
- `analyze51.py … analyze54.py` — **integrity-field crack trail (§5.13a)**: `analyze51` = trailing-byte
  semantics hunt (is there a checksum at all? first4 as build-timestamp, small-region CRC/sum/xor);
  `analyze52` = **differential CRC attack** (`CRC(m1)⊕CRC(m2)` cancels init/xorout for same-length
  messages ⇒ pin poly/reflection) + boundary-region hunt — **cracked footer + trailer as CRC16/MODBUS**;
  `analyze53` = UPG-orchestration string xref via indirect `.rodata` pointer tables; `analyze54` =
  explicit MODBUS verify on both revisions + exhaust first4@`0x400` hypotheses (packed CRC16 pairs /
  MODBUS-poly CRC32 / subregion CRCs — none ⇒ IV/nonce). The reusable `modbus()` table impl lives here.
- `analyze55.py … analyze58.py` — **usbdisk reference/overlay trail (§5.13b)**: `analyze55` = verify UPG
  string offsets in-image + scan u32-pointer/PC-relative refs (no absolute pointers exist);
  `analyze56` = structure inspection of the UPG-string cluster (interleaved Thumb function pointers =
  process-descriptor blocks) + scatter-load region table; `analyze57` = full PC-relative disasm of the
  usbdisk process @`0x03014E` (LDR-literal/ADR targets resolved → strings are base+offset referenced);
  `analyze58` = disasm the usbdisk state-2 **update worker** @`0x04FDFE` + BL-callee summary — reveals the
  overlay is **RAM-relocated** (static BLs miss FatFs), so trace via static targets in the normal cluster.
- `analyze59.py … analyze60.py` — **hook-anchor + FatFs-cluster identification (§5.13c/d)**: `analyze59`
  = full SRAM flash-writer disasm (file `0x91000–0x91200`: entry context, unlock/erase/program/verify,
  sector-table refs) + `f_mkfs` xrefs to the `MSDOS5.0`/`NO NAME` cluster; `analyze60` = identify
  `f_open/f_read/f_write/f_close` in the **normal** FatFs cluster anchored by `f_mkfs` (`0x037100`),
  `disk_write=0x038F28` + read counterpart, list all static BL callers of `disk_read/disk_write`.
- `analyze61.py … analyze65.py` — **FatFs API map + encoded-overlay discovery (§5.13b/d)**: `analyze61`
  = map the normal FatFs object-file cluster (prologues) + assess the usbdisk-caller region as a hook
  anchor; `analyze62` = anchor on the app's own `LOGS.BIN` writes (known-good `f_open/f_write` + FIL/path
  pattern), confirm `f_open`; `analyze63` = flash-writer literal-pool sanity + `f_write/f_read` confirm +
  **relocation check**; `analyze64` = `f_close/f_sync` hunt + **confirm the +2-byte pool shift is uniform**
  (encoded-overlay) + cave-space scan; `analyze65` = `f_close` candidate + app geometry (exact app end
  `0x080B14C0`, unused sector-9 tail `0x914C0..0xA0000` = 60 224 B for a cave).
- `analyze66.py` — **independent service-UPG verifier (§5.13e/f)**: re-derive key, re-decode, recompute
  both MODBUS CRCs + length + key-echo from scratch; check `SERVICE.UPG` byte-identical to stock; disasm
  the in-place `f_close` hook site (`0x0368E8` → `b.w` cave) + resume point (`f_close+4`) + the full cave;
  confirm cave-in-sector-9 and entry/first4/prefix preservation; disasm `f_sync`/`f_close` from stock. Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze66.py SERVICE.UPG SERVICE_DUMP.UPG ../extracted/MAIN_CCS2CHADEMO_1.UPG firmware.bin'`.
- `analyze67.py` — **`f_sync`/`f_close` finalizer identification (§5.13d)**: list all BL callers of
  `validate(0x036368)`, bound enclosing functions by push-prologues, disasm the small ones — pinpoints
  `f_sync=0x03685A` (flush dir-entry size) and `f_close=0x0368E8` (calls `f_sync` then clears `fp->obj.fs`),
  ruling out the no-sync `0x036A9C`. Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze67.py firmware.bin'`.
- `analyze68.py` — **scatterload region-table parser (§5.13b)**: reads the ARM `__scatterload` table at
  file `0x48A` (adr@`0x45E`), decodes each 16-byte `{load, exec, size, init_fn}` entry (offset-encoded
  init fn), and classifies exec addresses as SRAM/CCM/FLASH — proves **data-only relocation** (no code
  region ⇒ FatFs runs in place) and derives `.bss` end `0x20024D18` → the free-SRAM scratch gap. Run:
  `nix-shell -p python3 --run 'python3 analyze68.py firmware.bin'`.
- `make_service_upg.py` — **service-UPG builder (§5.13e/f)**: implements the cracked format/integrity —
  derive key, XOR-decode, patch app / append cave, re-seal length + both MODBUS CRCs, re-XOR; preserves
  prefix/entry/first4 verbatim. `STOCK -o OUT` (byte-identical round-trip), `--patch OFF:HEX`,
  `--dump-hook` (bootloader-dump cave, bench-confirmed), `--verify-only`. Emits `SERVICE.UPG` (safe,
  stock-equivalent) and `SERVICE_DUMP.UPG` (bench-confirmed working — produced `BOOT.BIN`).
- `SERVICE.UPG` / `SERVICE_DUMP.UPG` — built service images (§5.13e/f): `SERVICE.UPG` = byte-identical
  stock round-trip (safe recovery); `SERVICE_DUMP.UPG` = stock + one-shot bootloader-dump cave on the
  in-place `f_close` anchor (598 156 B, valid CRCs, **bench-confirmed working** — produced `BOOT.BIN`).
- `acq/dump/boot.bin` — **the acquired bootloader** (§5.14): 131 072 B (`0x20000`) dumped non-invasively
  by `SERVICE_DUMP.UPG`, RDP0, plaintext; triaged by `acq/analyze_boot.py` (vector table, reset startup,
  own flash writer, boot→app accessors, XMODEM-1K recovery, UPG component names, ID block).
- `REPORT.md` — this document.

## 8. Open questions / next steps

1. **Exact MCU part** — narrowed to **STM32F427/F429, 1 MB flash** (flash-writer’s 12-sector table, §5.6) + 192 KB SRAM + 64 KB CCM. Easiest: **read the MCU top marking** (e.g. `STM32F427VGT6`: V=LQFP100 / Z=LQFP144, G=1 MB) — this also gives the package needed for SWD pin numbers (§5.7). Else confirm via `DBGMCU_IDCODE` (`0xE0042000`, read by the app) / flash-size reg (`0x1FFF7A22`).
2. **App link base** — **CONFIRMED `0x08020000`** via the `.rodata` pointer table (§3.4), corroborated by the bootloader's app-base accessors (§5.14). Remaining: trace how the prefix/vector table is decrypted & placed and recover the prefix keystream/key — now possible on the acquired `acq/dump/boot.bin` (§5.14); no `BOOT_…UPG` needed.
2b. **Bootloader / update orchestration (bricking-critical)** — **ACQUIRED via the dump cave (2026-11-19, §5.14);** software search had found nothing (2026-11-17). The bootloader is a separate factory component at `0x08000000–0x08020000` (128 KB, sectors 0–4). It is **not in the RAR** (only `MAIN_…UPG`), **not elsewhere in the project**, and **not embedded in the app** — no real vector table; the lone `0x8F652` candidate is a misaligned `.rodata` pointer-table false positive (`analyze25/26`). **Not publicly downloadable:** vendor **Orientrise** (No. 355 Longjin Rd, Changzhou, Jiangsu) ships firmware **contact-only** — `support@orientrise.net` / `sales@orientrise.net`, phone/WhatsApp/WeChat `+86 181 0150 7071`; free firmware on request matched to vehicle/region, **no self-service portal and no `BOOT_…UPG` published**. The nearest open project **`uhi22/ccs32clara` / `osexpert/ccs32clara-chademo`** (Dongguan **Longood** OEM + rebrands EV-Boy / Akyga AK-SC-E18 / EVniculus / Autonlaturit) **explicitly lists Orientrise as NOT compatible** (Longood = STM32F407 + plain `My407ccs2chademo.bin`; Orientrise = F427/F429 + `.UPG`/XOR/encrypted prefix) and does **not** include its own OEM bootloader either — but its README independently corroborates §5.6: *"Firmware update logic is inside the bootloader, so this is not affected by the firmware."* **Acquisition paths:** (a) **email the vendor** for `BOOT_CCS2CHADEMO_1.UPG`; (b) **SWD dump** of `0x08000000` len `0x20000` — **bricking-safe procedure in §5.7** (ESP32-S3 CMSIS-DAP or ST-Link): reading is non-destructive at any RDP level, only an RDP 1→0 *unlock* erases — **never unlock**; probe the first 8 bytes to learn the level first. Once obtained, confirm: who reads USB first, the XOR/prefix decode + any whole-image verify, and any USB/SWD recovery mode. **Kit built (2026-11-18):** path (b) is implemented as the read-only, probe-gated **`acq/` kit** (§5.7 / §7) — SWD (ESP32-S3 CMSIS-DAP + OpenOCD) primary, UART/DFU system-bootloader fallbacks, `analyze_boot.py` triage; software-verified (command names + analyzer smoke-tested). **`boot.bin` acquired 2026-11-19 via the §5.13f dump cave** (no SWD hardware needed) → `acq/dump/boot.bin`, RDP0, triaged in §5.14. Remaining: trace the update orchestration + prefix-cipher key on the dump (interpretation only).
3. **The prefix block** (`0x58–0x400`) — **characterized** (§4.1): stream-cipher ciphertext (914 B) + plaintext footer `XIE22.00` / **u32 length = filesize−0x404** / u16 check `0x2DBE` (§4.1 corrected — the old "`0x10C0` + `9`" reading was the length's low/high halves). Ciphertext differs 913/914 B between C009/C013 ⇒ **per-image keystream (IV/nonce)**, key/routine in the bootloader (now acquired, §5.14 — recoverable from the dump). *(The `0x8C400–0x8E600` block is mbedTLS AES/SHA-256 tables, not encrypted data.)*
3b. **Bootloader→app entry contract — MAPPED; integrity CRACKED; service UPG BUILT (§5.12/§5.13).** Reset vector → file `0x40A`; file `0x400` = 10-byte header (4-byte IV/nonce + 6 constant bytes); startup sets MSP/PSP via bootloader-filled literals `0x44C`/`0x450`, zero-fills `.bss`, scatter-loads. Footer u16 + trailer = **CRC16/MODBUS** (recomputable, `analyze52/54`); the app does **not** verify a whole-image checksum. `make_service_upg.py` builds `SERVICE.UPG` (byte-identical stock round-trip, safe) + `SERVICE_DUMP.UPG` (bench-confirmed dump cave on the in-place `f_close` anchor). **Runtime model established (§5.13b):** the bootloader decodes the image on first boot after an upgrade and the scatterload relocates **data only** ⇒ FatFs runs in place; the free-RAM scratch gap is derived from `.bss` end `0x20024D18`. The corrected cave is **bench-CONFIRMED working** (§5.13h): it produced `BOOT.BIN` (`0x20000` B) — the bootloader is acquired (`acq/dump/boot.bin`, §5.14) and the runtime-model gate is closed. **Remaining:** (a) the exact entry address patched into literal `0x450`; (b) whether the **bootloader** adds a boot-time code check beyond the CRCs; (c) deeper bootloader RE on the dump — update orchestration, prefix-cipher key, exact app-jump, XMODEM/UPG-component parsing (§5.14).
4. **Pin map** — disassemble the GPIO init table (`0x67756…`) to map relays, e-lock, CP/PP ADC, QCA7005 SPI pins, CAN pins.
5. **CAN IDs & timing** — **LARGELY RESOLVED (§5.8).** Extracted: GB/T J1939 RX/TX/TP ID tables (SA `0x56`/`0xF4`), CHAdeMO H100–H112 + CBMS set, baud table {125,250,500} k @ APB1=42 MHz (SYSCLK 168 MHz **[H]**), CAN init/filter config, and protocol timeouts (1/4/5/6/8 s). **Remaining:** exact TIM2 prescaler / RTOS tick period + the numeric tick-constants behind the second-valued timeouts; CAN1/CAN2→CHAdeMO/GB/T assignment (needs pin map, item 4); confirm the runtime-built GB/T IDs (CHM/CTS/CRO/CST/CEM/BRM/BCP/BCS).
6. **QCA7005 firmware** — **RESOLVED: not in this update.** Modem boots from external SPI flash; the MCU is only a SLAC/PLC host (§5.3). For open firmware, use the redistributable Qualcomm blob (open-plc-utils / `qca_spi` ecosystem).
7. **RTOS identity** — locate the scheduler/task code to name the RTOS.
8. **EVCC identity details (§5.9)** — EVCCID = the adapter's **6-byte PLC MAC** (confirmed: SLAC EVHost-MAC, `MAC:` prints, and `SessionSetupReq` all use the same global-struct bytes via thunk `0x080890AE`). **Remaining:** (a) trace the exact **QCA7005 MAC-read MME** over SPI1 that populates the global EVCC/SLAC struct at init (the MAC value is runtime/per-unit, not a fixed constant — no OUI or STM32-UID derivation found); (b) the **SDP security-flag trigger** — when `0x10` (TLS) vs `0x00` (no TLS) is requested (`0x000900`), i.e. its dependence on DIN-vs-ISO mode / contract-cert availability.
9. **Device provenance (§5.10)** — vendor **disavows the unit as a clone**; firmware nameplate = **`KM-CCS2CHAdeMO-1`** / `CCS2GBT` with CATL/CAMA BMS code. Identify the **"KM" OEM**: web search was unavailable (2026-11-18, retry); decode the ID-block fields `F$K$N$T$2005$TY/VR$…` (f+0x090df0); check enclosure/label markings and the `SER:202406180463` date-code convention against other units. The USB log **proves the unit runs C009 = `firmware.bin`** (§5.10), so all RE findings apply to this hardware regardless of brand. MAC OUIs are IEEE-RA reference values — not a maker fingerprint.