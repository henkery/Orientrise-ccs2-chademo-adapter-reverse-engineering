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
each image. The prefix block is high-entropy beyond this XOR, but the running-app dump (§5.16) proves
it is a **discarded header field** — the boot strips `0x402` bytes and installs `fw[0x402:]` verbatim, so
there is **no prefix cipher** (the boot's split-table routine is CRC16/MODBUS integrity, §5.15). The
"protection" is the 2-byte XOR + header strip only (§6).

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

**Sub-family discriminators (`analyze71`, correct-base peripheral scan):** the firmware references
**no** F429/F439-only blocks — LTDC (`0x40016800`), DMA2D (`0x4002B000`), SAI1 (`0x40015800`), FMC
(`0xA0000000`) — and **no** F437/F439 crypto — CRYP (`0x50060000`) / HASH (`0x50060400`). RNG
(`0x50060800`) **is** present (⇒ not F427xG-without-RNG variants). It reads `DBGMCU_IDCODE`
(`0xE0042000`) at f+`0x30388` & f+`0x67802` and the 96-bit UID (`0x1FFF7A10`) at f+`0x68406`; the
flash-size register (`0x1FFF7A22`) is **not** read. F427 and F429 share IDCODE `0x419`, so the
firmware alone cannot separate them — the exact part number needs the package top marking. Net:
**STM32F427/F429 (IDCODE 0x419), no display/crypto, RNG on**; GD32F450/470 clone not fully excluded.

### 3.4 Flash / link base  [C]
- Flash at `0x08000000` (STM32F4). App is **bootloaded**: string `BOOT_CCS2CHADEMO_1.UPG` present.
- **CORRECTED by the running-app dump (§5.16, `analyze70`):** the true mapping is
  `address = 0x0801FBFE + file_offset` (i.e. `fw[0x402]`→`0x08020000`). The boot strips a `0x402`-byte
  header and installs `fw[0x402:]` **verbatim** — 100% byte match vs `acq/dump/app5.bin`, zero patches.
  The earlier `.rodata` pointer-table result ("166/231 at base `0x08020000`", `fw[0x400]`→`0x08020400`)
  was **off by `0x402`** and is superseded.
- So: file `0x402`→`0x08020000` (the 8-byte vector SP+reset), **Reset_Handler at file `0x40A`→`0x08020008`**.
  The `0x000–0x402` header + "encrypted prefix" + footer are **stripped/discarded** — the prefix is never
  installed or decrypted (§5.16); the vector SP+reset (`fw[0x402:0x40A]`) install verbatim and the app
  self-bootstraps from them (§5.12 corrected / §5.16).
- `0x08020000 − 0x08000000 = 0x20000` ⇒ **128 KB bootloader** at `0x08000000–0x08020000`.

---

## 4. Image layout (decoded offsets)

| offset | size | entropy | content |
|---|---|---|---|
| `0x000000–0x000058` | 88 B | text | `$$…` header (§2.2) |
| `0x000058–0x000400` | 936 B | 7.81 | **[C] high-entropy header field (914 B) + 22 B plaintext footer** (`XIE22.00` + fields). **DISCARDED by the boot** (inside the stripped `0x402` header) — never installed/decrypted; NOT a vector table (§5.16 supersedes the §4.1 cipher hypothesis) |
| `0x000400–0x00040A` | 10 B | — | entry header: 2 discarded bytes + **8-byte vector SP+reset** (→`0x08020000`); **Reset_Handler at `0x40A`** (= `0x08020008`), then app code + rodata (§5.16) |
| `0x000D00–0x02xxxx` | — | low/med | debug-string tables (SLAC/TCP/TLS/SDP/ISO15118/CHAdeMO/GB/T) |
| `0x067700–0x067C00` | — | code | RCC/FLASH/GPIO/CAN/SPI init (STM32 HAL-style) |
| `0x0738C0–0x073960` | — | code | **[C] QCA7005 SPI1 byte-level host driver** (full-duplex `SPI_DR` exchange, `0xAA`/`0x55` sync, buffer-write loop) |
| `0x08C400–0x08E600` | ~8.7 KB | high | **[C]** mbedTLS crypto tables — AES S-boxes (`0x8C4D6`, `0x8D5D6`), SHA-256 constants (`0x8EB2E`, `0x8F126`); high entropy = fixed lookup tables, not encrypted data. `.rodata` pointer tables start interleaved here (`0x8CCD2`) |
| `0x08E800–0x0914C4` | ~11 KB | very low | **[C] `.rodata` absolute pointer + string tables** — 32-bit flash addresses `0x080Axxxx`/`0x080Bxxxx`, records `{str_ptr, count, ptr, ptr, ptr}`; these pin the link base (§3.4) |

**CORRECTED (§5.16):** the vector SP+reset are the 8 bytes `fw[0x402:0x40A]` (`18 4D 02 20 09 00 02 08`
= SP `0x20024D18`, reset `0x08020009`), installed **verbatim** at `0x08020000`. The earlier "no SP word in
the clear ⇒ vector table hidden in the encrypted prefix" reading missed it because the search used the
wrong base (`0x08020000` instead of `0x0801FBFE`) and treated `fw[0x400:0x404]` as an opaque IV. The
high-entropy `0x58–0x3EA` block is a **discarded** header field, not a vector table (§5.16).

### 4.1 The encrypted prefix (`0x58–0x400`)  [C characterization · H contents]

> **SUPERSEDED (§5.16):** the running-app dump proves this block is a **discarded header field** — the
> boot strips `0x402` bytes and installs `fw[0x402:]` verbatim, so `0x58–0x3EA` is never installed or
> decrypted. There is **no prefix cipher**; the "first4 IV" is not an IV (2 discarded bytes + the SP low
> halfword). The stream-cipher analysis below is the historical investigation trail, kept for provenance.

- **936 B = 914 B high-entropy field + 22 B plaintext footer.** Entropy 7.81.
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
  value, not a fixed key. The prefix is encrypted beyond the outer XOR; the boot's split-table routine
  is **CRC16/MODBUS integrity, not the cipher** (§5.15) — the prefix-decrypt question is now **CLOSED**:
  there is no cipher, the prefix is discarded (§5.16).
  **Integrity fields cracked (§5.13, `analyze52/54`):** the footer u16 `0x3FE` =
  **CRC16/MODBUS**(`dec[0x3EA:0x3FE]`) and the trailer u16LE @`n−2` = **CRC16/MODBUS**(`dec[2:n−2]`),
  with `dec[n−4:n−2] == 00 00` (key echo) — verified on **both** revisions. MODBUS = poly `0x8005`
  reflected (`0xA001`), init `0xFFFF`, refin/refout true, xorout 0. The first-4-bytes at `0x400` are
  **not** a CRC of any region — historically read as a per-image IV/nonce, **disproven** (2 discarded
  bytes + SP low halfword, §5.16). Both CRCs are recomputable, so a
  patched/extended image can be re-sealed (`make_service_upg.py`, §5.13). The earlier "no standard CRC"
  result (`analyze44/47/49/50`) missed MODBUS because it tested the wrong byte ranges / init values.

- **Contents — RESOLVED (§5.16):** NOT a vector table. The block is **discarded** by the boot (inside the
  stripped `0x402` header); its high entropy is encrypted metadata or decoy, irrelevant to execution. The
  real vector SP+reset are `fw[0x402:0x40A]`, installed verbatim. There is **no decrypt routine** (the
  exhaustive boot trace, §5.15, correctly found none). For an open firmware this is a non-issue: supply
  any prefix bytes and re-seal the trailer CRC; the vector + app code live at `fw[0x402:]`.

---

## 5. Software architecture (from strings & code)

### 5.1 RTOS — uC/OS-II (Micrium), customized  [C identified]
**RESOLVED (§8.7, `analyze73`):** the RTOS is **uC/OS-II**, identified by the internal-symbol debug
string `OS Information | OSRdyTbl:%05x | RUN: %u:%02u:%02u` (f+`0x2F042`). **`OSRdyTbl`** is the
uC/OS-II ready table (uC/OS-III uses `OSRdyList`); the earlier "not uC-OS by name" search missed it
because it looked for the product name, not the internal symbol.
- **Tick = 100 Hz (10 ms):** the stat dump's `RUN: h:m:s` math divides the tick counter (`OSTime`,
  accessor `0x0808981C`) by **100** → seconds, then 60/60 (§5.8).
- **Task-stat dump** (`Task RT BASE IER SS STKF STKS ADDR NAME`, row format
  `%4lu %6lu %06x %3lu %2lu %4lu %4lu %08x %s`) iterates TCBs via accessor functions
  (get-TCB-by-index `0x080895CA`, stack-free `0x080895EC`, stack-size `0x08089614`). The TCB layout
  is vendor-customized (fields at `+0x00` ptr, `+0x04` byte, `+0x06` hword, `+0x0C` ptr, `+0x14` ptr,
  `+0x28`, `+0x3C`).
- **Task creation** is a customized `OSTaskCreateExt`-style wrapper @`0x08088D76`:
  `(task_func, name_str, ?, pdata, stk_base, stk_size)`, priority set separately (e.g.
  `tcpip_process`: `0x1000` = 4 KB stack, priority 10). Named processes: `tcpip_process`,
  `led_process`, `PDS_PROCESS`, `iso1_function_res_process`, plus per-protocol state-machine tasks.

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
  **ADC-channel→signal map RESOLVED + NAMED (§5.5b, `analyze77`): CP DC level = PA0/ADC3_IN0 (`AD_CPD`),
  PP = PA2/ADC3_IN2 (`AD_PP`); CP PWM duty/freq = TIM4_CH1 input-capture on PD12 (not ADC).**
- Connector **e-lock**, **precharge**, **welding detection**, **insulation/isolation**,
  contactor/relay drive (`precharge_relay failed!terminate`), emergency/timeout shutdown.
- **CP PWM capture = TIM4_CH1/PD12** (input-capture, slave-reset period measurement, §5.5b) — the earlier
  "TIM2 ⇒ CP PWM" guess was wrong; TIM2 is a busy-delay timer (§8.5). **CAN1/CAN2** ⇒ CHAdeMO + GB/T BMS.

### 5.5a GPIO pin map — DECODED (`analyze74`)  [C]
**RESOLVED (§8.4).** The board GPIO init @ runtime `0x08087010` (f+`0x67412`) writes a literal pool of
**standard STM32F4 GPIO register values** per port (GPIOA–E), then calls a GPIO-lock helper
@`0x08087340` (f+`0x67742`, `LCKR` key sequence) with mask `0xFFFF`. The "packed config table" at
f+`0x67756` is just that literal pool — **not** a custom format (the earlier §8.4 guess was wrong; the
parser was found by hunting LDR loads whose pool *location* falls in the table, `analyze72`). Bus pins:

| function | pins | AF |
|---|---|---|
| **SPI1 — QCA7005 PLC modem** | PA5 SCK / PA6 MISO / PA7 MOSI | AF5 |
| **SPI4 — storage flash** | PE12 SCK / PE13 MISO / PE14 MOSI | AF5 |
| **USART1** | PA9 TX / PA10 RX | AF7 |
| **USB OTG FS** | PA11 DM / PA12 DP | AF10 |
| **CAN1** | PD0 RX / PD1 TX | AF9 |
| **TIM4_CH1 — CP PWM input-capture** | PD12 | AF2 |
| **ADC analog inputs** (named §5.5b) | PA0=`AD_CPD`(CP), PA1=`+24V`, PA2=`AD_PP`(PP), PB0/PB1=`HV` diff, PC2=`AD_BAT` | — |

GPIO outputs (relay / e-lock / LED / contactor drive, exact signal names pending): PA4; PB10/PB11/PB14/PB15;
PC5/PC9; PD3/PD8/PD11; PE4/PE7/PE8/PE11/PE15. PA13/PA14 left as inputs (SWD not claimed by the app).
**CAN2 has no AF9 pins in this init** (PB5/PB6/PB12/PB13 left as inputs) ⇒ its GPIO is configured elsewhere
or the board wires only CAN1 — **CAN1/CAN2→CHAdeMO/GB/T assignment still pending** (§8.5). Full per-pin
mode/AF/pull/open-drain/initial-level table: `analyze74.py`.

### 5.5b ADC channel→signal map — DECODED + NAMED (`analyze77`)  [C]
**RESOLVED (§8.4).** The analog front-end is named by the firmware's own **"Hardware Information"**
diagnostic dumper @`0x0804E92C` (f+`0x2ED2E`): it calls each ADC getter and prints the result against a
label string (f+`0x2F0FA`–`0x2F1AE`), so the channel→signal binding is read straight from the firmware,
not guessed. The ADC init @`0x08087B7E` (f+`0x67F80`) sets up **ADC1+ADC2 in dual regular-simultaneous
mode** (`ADC_CCR=0x0002A006`, MULTI=6) and **ADC3 independent**, all triggered by **TIM8_TRGO**
(CR2 EXTSEL=1110, EXTEN=rising); DMA2_Stream0_CH0 reads the packed `ADC_CDR` (ADC2<<16|ADC1) → buffer
`0x200225E8`, DMA2_Stream1_CH2 reads `ADC3_DR` → `0x20022628` (both circular, NDTR=16). Regular sequences
(SQR1/2/3): **ADC1 = 8× ch8 (PB0)**, **ADC2 = 8× ch9 (PB1)**, **ADC3 SQ1..8 = [1,2,1,2,1,12,1,0] =
PA1,PA2,PA1,PA2,PA1,PC2,PA1,PA0**. The DMA half/full-transfer ISRs (`0x08087CA8` / `0x08087D56`) accumulate
into a context struct @SRAM `0x20000988`; scaled getters bind each field to a pin (full-scale = samples×4095):

| signal (dumper label) | pin / channel | getter | scaling | meaning |
|---|---|---|---|---|
| **`AD_CPD`** | **PA0 / ADC3_IN0** | `0x08087E64` | Σ8·PA0 ×3300/32760 | **CP (Control Pilot) DC voltage level** (state A–F) |
| **`AD_PP`** | **PA2 / ADC3_IN2** | `0x08087E3C` | Σ16·PA2 ×3300/65520 | **PP (Proximity Pilot) voltage** |
| `AD_BAT` | PC2 / ADC3_IN12 | `0x08087E50` | Σ8·PC2 ×6600/32760 | battery voltage (6.6 V FS ⇒ 2:1 divider) |
| `+24V` | PA1 / ADC3_IN1 | `0x08087E26` | duty-reconstructed | +24 V rail monitor |
| `HV` | **PB0−PB1** (ADC1_IN8 − ADC2_IN9) | `0x08051D38` | Σ(PB0−PB1), 3125-event avg → `0x20000878` | **DC-link high voltage** (differential isolated sense) |

**CP is split across two peripherals:** its **DC level** (for state detection) is the ADC channel PA0
(`AD_CPD`); its **PWM duty/frequency** are **not ADC** — they are **TIM4_CH1 input-capture on PD12 (AF2)**
(init `0x08088078`: CCMR1 CC1S=01 input on TI1, SMCR=0x54 slave-reset-on-TI1FP1 ⇒ period measurement,
PSC=83/ARR=1110 ≈ 1 kHz, DIER=CC1IE+CC2IE). The capture ISR `0x080880BA` reads CCR1/CCR2 + GPIOD bit12,
validates period ≈ 950±100 ticks (1 kHz), computes duty×1000 and feeds a **16-entry sorted-insertion median
filter** (`0x0808818A`, buffer `0x20022688` → ctx `0x200009C0`): `CP_DUTY`=get[8] (`0x08088144`),
`CP_FREQ`=get[6] (`0x08088158`). The duty is decoded to **available current by the IEC 61851-1 law**
(`0x08051E02`): valid 8–97 % (`ac cpduty_err! not nominal(8%-97%)!`); <10 %→6 A; 10–85 %→`(6·d+50)/100`
= 0.6·d A; 85–96 %→`(25·d−15950)/100` = 2.5·(d−64) A; 96–97 %→80 A; else 0. A companion classifier
(`0x08051E70`) maps duty to the **state char** printed in `#SLAC: CP DUTY is '%c'[%.1u][%u],PP=%u`:
`'5'` (3–7 % = the **DIN/ISO 5 % digital-communication mode**, `CP_ST_DUTY_5` checked by SessionSetupRes /
PaymentSelectionRes / ContractAuthenticationRes), `'M'` (7.5–97 % nominal PWM), `'0'` (0 %), `'1'` (100 %),
`'N'` (invalid). `CP_ST` getter `0x08051EDC` returns `'E'` (no duty) / `'B'`/`'C'` (duty + PD11 level).
**PP state** (`PP_ST`, getter `0x08051DBC`) = an `AD_PP` voltage **window detector** `0x08051D7A`
(2146/2296 mV thresholds, debounce 4 → flag `0x2000087C`). The remaining dumper rows are `KEY_LOCK`
(connector e-lock, `0x08087AEE`) and `PLC LINK`/`INT` (QCA7005). Re-derived from bytes by `analyze77.py`.

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
`UPGRADE:[%u]…` version/date log). The prefix block is high-entropy beyond this XOR, but the running-app
dump (§5.16) proves it is a **discarded header field**, not ciphertext the boot decrypts: the boot
XOR-decodes, strips `0x402` bytes, and installs `fw[0x402:]` **verbatim** (no cipher). So the app reads
the UPG and writes it to flash in its raw/obfuscated form, then resets; the **bootloader XOR-decodes +
CRC-verifies, strips the header, and installs/launches the app** (the outer XOR-decode can be done by
either side from the self-described key). **The outer-key change across revisions is therefore not a
compatibility barrier; any version/hardware check is the real gate** — the orchestration is traced on the
acquired dump (§5.15) and the install transform confirmed by the sector-5 dump (§5.16).

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
- **CAN1/CAN2 → CHAdeMO/GB/T assignment:** pin map now decoded (§5.5a) — **CAN1 = PD0/PD1 (AF9)**; CAN2
  has no AF9 pins in the board init (configured elsewhere or CAN1-only board), so the per-protocol bus
  assignment is still pending (§8.5).

#### 5.8.2 CAN controller init  [C]

Init routine @ `0x67854` (both controllers, HAL-style):
- `MCR = 0x4D` — INRQ (enter init), TXFP, RFLM (RX-FIFO locked), NART (no auto-retransmit), ABOM (auto bus-off recovery).
- `IER = 0x8003` — TX-mailbox-empty + FIFO0-message-pending + sleep interrupts.
- Filters: `FMR` `0xE01→0xE00` (**CAN2SB = 14**, CAN2 filters start at bank 14); `FM1R = 0` (mask mode),
  `FS1R = 0x0FFFFFFF` (32-bit scale), `FFA1R = 0` (all → FIFO0), `FA1R = 0x4001` (**banks 0 & 14 active**).
  Bank 0 regs @ `+0x240` (CAN1), bank 14 @ `+0x2B0` (CAN2). Init leaves a **placeholder filter (ID=0)**
  that the protocol layer reconfigures with the real acceptance IDs/masks.

**Driver mailbox-FIFO layer (`analyze72`, f+`0x67A40`+ / runtime `0x0808763E`+):** above the HAL init
sits a software ring-buffer driver keyed off a per-controller SRAM handle (CAN handle base
`0x200216DC`, loaded via LDR-literal pool f+`0x67B72`). Layout: TX ring head/tail halfwords at
handle`+0xF00`/`+0xF02`, RX ring head/tail at `+0xF04`/`+0xF06`, an enable byte `+0xF09`; RX mailbox
array at `+0x180`, TX mailbox array at `+0x1B0`, **3 mailboxes** each (loop `cmp #3`). Each mailbox
slot is 12 bytes (`r4 + r4<<1` then `<<2` = ×12): word0 = ID/RTR/IDE packed, word1/word2 = data.
The RX path (`0x08087674`) drains FIFO0 into the ring (tail`+0xF06` advances, `uxtb` wrap); the TX
path (`0x080876EA`) pushes ring frames into empty mailboxes (head`+0xF00` advances, `&0x3F` wrap =
64-deep ring). Acceptance masks seen in the pools: `0x0003FFFF` (29-bit extended-ID mask),
`0x1FFFF800`, `0x00010101`. CAN handle tables in rodata: CAN1 `{base 0x40006400, cfg 0x20000978,
0x000F0F0F}` @ f+`0x67B76`; CAN2 `{base 0x40006800, …, 0x00010101, NVIC_ISER 0xE000E200,
0x0003FFFF, 0x1FFFF800}` @ f+`0x67B82`.

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
- **RTOS tick = 100 Hz (10 ms) [C, `analyze73`]:** the uC/OS-II task-stat dump (§5.1) converts the
  `OSTime` tick counter (accessor `0x0808981C`) to seconds by `÷100`, then `÷60`/`÷60` for the
  `RUN: h:m:s` field — so the OS tick period is **10 ms**. This is the timebase the second-valued
  protocol timeouts count against.
- **Inference [H] (busy-delay only):** busy-unit ≈ 1 µs ⇒ TIM2 tick ≈ 10 µs (100 kHz), independent of
  the OS tick. Exact **TIM2 prescaler not yet confirmed** (the timer @ `0x6847A` with PSC=83/ARR=1110
  is a ~1.111 ms PWM, *not* the free-running TIM2 timebase). The numeric tick-constants behind the
  second-valued timeouts remain to be extracted from the state machines.

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
**Trigger RESOLVED + NAMED — PnC root-certificate count (`analyze76`):** `r0` is the return of accessor
`0x08051074`, which reads a config struct @SRAM `0x200189EC` (word +`0x20`, byte +`0x24` packed at bit
24); the tested **low byte (`0x20018A0C`) = 0 ⇒ TLS, nonzero ⇒ no TLS**. That byte is named by the
firmware's own diagnostic dumper `0x0804EB5C` (**"Show Certification Status"**, f+`0x2F2CA`): it is the
**"Root certs" count** — config[+`0x20`] = number of configured **Root-CA certificate** entries (vendor
V2G msg-code **`0x8101`**, ≤5), with config[+`0x21`] = "Pri_root cert" (`0x8102`), [+`0x22`] = "Oem cert"
(`0x8105`), [+`0x23`] = "Contract certs" (`0x8109`, 32-byte payload). Flash parser `0x08050E14` copies the
msg-`0x8101` entries from the PnC certificate config block @`0x001F8010` (header @`0x001F8000`, magic
`0xCEA155E1`, ver 1) into a 5-slot array; config init `0x08050B94` counts the populated slots
(`strb r8,[cfg+0x20]`). So the trigger is the **ISO 15118 PnC root-certificate configuration** (a
service-config property) — *not* the DIN-vs-ISO appHandshake SchemaID choice (that is the separate
`0x013F50` selection below) and *not* a per-session value. (The earlier msg-code list
`0x8101/0x8105/0x8107/0x8108/0x810D` was wrong: the parser tests `0x8101`–`0x8109`; `0x810D` does not
exist — it conflated the parser with the `0x8106/07/08` builder.)
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

**MAC source — call chain + MAC-read MMTYPE RESOLVED [C] (`analyze75`):** the value is **runtime, not a
fixed constant** — held in the global EVCC/SLAC struct (SRAM `0x200003D0`) and populated from the
**QCA7005 modem** PIB MAC (fw `1.1.0.727-02-20130826`, banner `MAC-QCA7005-…` f+`0x2596`). No hardcoded
OUI and no STM32-UID-derived MAC (`0x1FFF7A10` unreferenced). MAC-init chain (`analyze72`): the SLAC
state machine logs the banner, then `0x0802156C` → `0x08088C10` (SPI mutex `0x20000A00` + **PC5** reset
pulse, BSRR `0x200000`→`0x20`) → `0x08088B94` (poll QCA7005 SPI reg `0x1A00` for CPU-ready signature
`0xAA55`, then reg `0xC00` bit 6) → `0x08088A0E` (SPI register init: `0x1200=0xC5B`, `0xC00=0x447`,
`0xD00=0x41`; reg read `0x080932A8` / write `0x080932EC`).

**MAC-read MME — MMTYPE `0xA000` (REQ) / `0xA001` (CNF) (`analyze75`):** after SPI init the host reads
the modem PIB MAC with a **vendor-specific MME (MMTYPE `0xA0xx`, MMV `0`)**, EtherType **`0x88E1`**
(HomePlug AV / IEEE 1901). Builder `0x08088B48` copies a 12-byte MAC header from template `0x080AEC84`
(dest = QCA7005 **default** PIB MAC `00:B0:52:00:00:01`, src = host `FE:FF:FE:FF:00:01`), writes the
EtherType via `movw #0xE188`+`strh` (network order ⇒ on-wire `88 E1` — why a static-template scan misses
it), MMTYPE low/high `00`/`A0`, payload **param `0xB000` + op `'R'` (`0x52`, Read)** + 4 zero bytes, then
`mme-send` `0x080888CE` (len `0x18`=24). The reply CNF `0xA001` is validated by `0x08088ADA` (checks
MMTYPE low==1/high==`0xA0`, stamps done-marker `0x55`) and copied to SRAM `0x200227E0`; the **6-byte MAC
lands at `0x200227E6`** (=+6), returned by accessor `0x08088CAC` — the same bytes used as SLAC
EVHost-MAC and `SessionSetupReq` EVCCID. Poll loop `0x08088B1E` (10 ms × 20) inside retry wrapper
`0x08088C74` (×3). The dest is the *default* MAC because the real one is not yet known — the `0xA000`
read returns the actual per-unit MAC. This PIB read is distinct from the SLAC `CM_*` MMEs (MMTYPE
`0x6064/65` `CM_SLAC_PARM`, `0x606A` `CM_START_ATTEN_CHAR`, `0x6008/09` `CM_SET_KEY`; decoder
`0x080214D6`, builder `0x0802166E`/`0x0802188C`), which run *after* the MAC is known (§8.8).

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

**Caution:** clone unit; any version/hardware check in the bootloader is the real compatibility gate
(§5.6). The bootloader is dumped (`acq/dump/boot.bin`, §5.14), the update orchestration traced (§5.15),
and the install transform confirmed by the running-app dump (§5.16): the boot strips a `0x402`-byte header
and installs `fw[0x402:]` verbatim — the high-entropy "prefix" is a **discarded header field**, not a
cipher (the boot's S-box routine is CRC16/MODBUS integrity). There is **no prefix-decrypt**.

### 5.12 Bootloader → app entry contract (service-firmware basis)  [C structure · H launch details]

> **CORRECTED (§5.16, ground-truth dump):** the contract below was traced with the wrong link base
> (`0x08020000` instead of `0x0801FBFE`) and is superseded. The real contract: `fw[0x400:0x40A]` =
> [2 discarded bytes][8-byte vector SP+reset]; Reset_Handler `fw[0x40A]`→`0x08020008` self-bootstraps
> (SP from its own `vector[0]`, zero SRAM+CCM, scatterload, `__main`); **the boot patches nothing** — the
> "`0x44C`/`0x450` bootloader-filled placeholders" and "first4 IV/nonce" were wrong-base artifacts. The
> bullets below are the historical trail; see §5.16 for the verified contract.

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
- **Two literal-pool words were *thought* to be bootloader-filled placeholders** (`0x44C` = `0x0000BBC3`,
  `0x450` = `0x00550802`, identical in C009 & C013). **DISPROVEN (§5.16):** with the true base these are
  ordinary app code/data, **not patched** — the boot installs `fw[0x402:]` verbatim (zero mismatch bytes).
  The real startup pools are `APP5+0x4C` (`=0x08020000`, the vector base) and `APP5+0x50` (`=0x08020055`,
  the entry), both stock. **A service firmware needs no special stub at `0x44C`/`0x450`.**
- **Integrity fields cracked (§5.13):** footer u16 `0x3FE` = CRC16/MODBUS(`dec[0x3EA:0x3FE]`);
  last-4-bytes trailer = `00 00` key-echo + u16LE CRC16/MODBUS(`dec[2:n−2]`) (C009 `00 00 9F 00`,
  C013 `00 00 D6 10`). Both recomputable ⇒ a rewritten/extended app can be re-sealed. The
  first-4-bytes `0x400` are **not** an IV/nonce (2 discarded bytes + SP low halfword, §5.16). The
  boot-time code check is **resolved** (CRC16/MODBUS + config additive checksum, no whole-image hash, §5.15).

**Service-firmware consequence (non-invasive bootloader dump):** the prefix + footer can be
**reused verbatim** from a stock UPG (or replaced with any bytes + a re-sealed trailer CRC) — the boot
strips the `0x402` header and installs `fw[0x402:]` verbatim, **no decrypt, no patching** (§5.16). Keeping file `0x000–0x45E` (header + prefix +
footer + entry header + startup stub) byte-for-byte stock and replacing only the application code the
stub jumps to is the lowest-risk way to get a **vendor-bootable** service image that reads
`0x08000000–0x08020000` out to USB and can re-flash a stock `MAIN_…UPG` to back out. **Implemented:**
`make_service_upg.py` (§5.13) reuses the stock prefix/entry verbatim, applies app patches / appends a
dump cave, and re-seals both MODBUS CRCs + the length field — `SERVICE.UPG` round-trips byte-identical
to stock (safe recovery image); `SERVICE_DUMP.UPG` adds a one-shot bootloader-dump cave on the in-place
`f_close` anchor (§5.13f). **Bench-confirmed working (§5.13h):** it dumped the bootloader to USB
(`acq/dump/boot.bin`, §5.14) — the runtime model (FatFs in place, scatterload-derived free RAM) is
established (§5.13b) and the original non-invasive acquisition goal is met. The `acq/` SWD kit (§5.7)
remains an alternative dump path. **All interpretation tasks resolved (§5.16):** entry = `0x08020054`
(stock pool `APP5+0x50`, no patch); **no prefix-decrypt** (prefix discarded, verbatim install); the
boot-time code check is resolved (CRC16/MODBUS + config additive checksum, no whole-image hash, §5.15).

### 5.13 UPG integrity cracked, encoded-overlay pack, and the service-UPG builder  [C fields · C runtime model · C cave]

**(a) Integrity fields = CRC16/MODBUS (recomputable).** The trailing bytes are memory-integrity
*metadata*, not a secret and not an app-enforced gate (`analyze51/52/54`, confirmed C009 **and** C013):

| field | offset | value / coverage |
|---|---|---|
| length | u32LE `0x3F2` | `filesize − 0x404` (app-code byte count) |
| footer CRC | u16LE `0x3FE` | **CRC16/MODBUS**(`dec[0x3EA:0x3FE]`) — over the 20-byte footer itself |
| trailer | `dec[n−4:n]` | `00 00` (key echo) + u16LE **CRC16/MODBUS**(`dec[2:n−2]`) — over the whole body |
| first4 | u32 `0x400` | 2 discarded bytes + SP low halfword — **not** an IV (§5.16); kept stock |

MODBUS = poly `0x8005` reflected (`0xA001`), init `0xFFFF`, refin/refout true, xorout 0. The earlier
"no standard CRC" hunts (`analyze44/47/49/50`) missed it by testing wrong ranges/inits; a **differential
CRC attack** (`analyze52`: for same-length messages `CRC(m1)⊕CRC(m2)` cancels init/xorout) pinned the
poly, then `analyze54` verified both fields explicitly. **The app updater does NOT verify a whole-image
checksum** — there is no CRC32 routine in the app; the writer only does per-word flash read-back (§5.6).
So the CRCs are recomputable and any boot-time whole-image check would be **bootloader-side**.

**(b) Encoded-overlay: literal pools are +2-byte packed — LOCAL to the SRAM-copied flash writer.**

> **CORRECTED (§5.16):** the `+2` pool pack is real **only for the SRAM-copied flash writer** (its pools
> stay encoded in flash, fixed up at SRAM-copy time). All **in-place** code (FatFs, reset handler, app) is
> **plaintext verbatim** after the `0x402` header strip — the "FatFs pools halfword-swapped" / whole-image
> "storage-pool decode" framing below was a wrong-base (`0x402`) artifact. Historical trail kept.

The flash writer's literal pools are **shifted +2 bytes** relative to where the LDR-literals point (`analyze63/64`):
- Flash writer: unlock keys `0x45670123`/`0xCDEF89AB` sit at file `0x9118E`/`0x91192`, but the
  LDR-literals reference `0x9118C`/`0x91190`; FLASH base `0x40023C00` is at `0x9118A` while the code
  loads `0x91188`.
- FatFs pools likewise: stored `0xBCB82001` → swap16 → `0x2001BCB8` (a valid SRAM address).

⇒ the flash writer is **not directly executable from the stored bytes**; its pools are fixed up at
SRAM-copy time. **In-place code is plaintext verbatim** after the `0x402` header strip (§5.16). The
`usbdisk` overlay (`0x02FF00–0x030300`) was thought **RAM-relocated** (its 32 BLs hit zero FatFs targets;
its strings have zero static xrefs — `analyze57/58`), but that test used the wrong base; re-check with
base `0x0801FBFE` (§5.16). This is a light local pack, not crypto.

**Bootloader-decode model (confirmed; refined §5.16).** The bootloader **unobfuscates the image on first
boot after an upgrade** — XOR-decode + `0x402`-byte header strip, then a **verbatim** install to flash
(§5.16) — then hands off to the app, which runs normally on subsequent boots. Evidence: the device log shows a `RESET`/system-init pass after each
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

**(i) `SERVICE_DUMP_APP5.UPG` — running-app sector-5 dump cave (`--dump-app5`).** The same bench-confirmed
`f_close` cave (f) retargeted from boot sector 0 to the **running app's sector 5**: `f_write(&FIL,
0x08020000, 0x20000, &BW)` → `0:/APP5.BIN`, one-shot magic `0x2003D005` (distinct from boot's
`0x2003D00D` so the two variants can't suppress each other). It captures the running app's first 128 KB
— the vector SP+reset (`APP5[0:8]`), the Reset_Handler + startup, and the in-place code — as ground-truth
plaintext for diffing against the stored `firmware.bin`. **Bench result (§5.16, `analyze70`):**
`APP5[x] == fw[x+0x402]` for all 128 KB (100%, 0 mismatch runs) ⇒ the boot strips a `0x402`-byte header and
installs `fw[0x402:]` **verbatim** — no prefix cipher, no boot-time patch. (The earlier "entry literals
`0x44C`/`0x450`" and "recover the prefix keystream by known-plaintext" rationale were wrong-base
artifacts, superseded by §5.16.)
**Read-only:** the cave only reads flash and writes USB; it never programs flash, so the stock
update/recovery path is untouched. **Verification (`verify_app5.py`, independent of the builder):** both
MODBUS CRCs, length, key-echo, prefix/entry/first4 verbatim, hook→cave + resume `f_close+4`, scratch
`FIL/BW/FLAG`, and cave-in-sector-9 all pass; decisively, the decoded image differs from the
**bench-proven** `SERVICE_DUMP.UPG` in **only 9 bytes** — the two magic low-halfword immediates
(`0x0D→0x05`), the dump-base high halfword (`0x00→0x02`, i.e. `0x08000000→0x08020000`), the four path
characters (`BOOT→APP5`), and the two trailer-CRC bytes that follow from those. Same 598 156 B footprint,
so it inherits the proven cave's safety guarantees (in-place anchor, free-RAM scratch, recursion-safe
epilogue). **Bench-confirmed:** produced `APP5.BIN` = `0x20000` B → `acq/dump/app5.bin` (§5.16).

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

**Deeper RE on the dump (§5.15):** the app-jump sequence, update orchestration + external-SPI storage
model, UPG component parsing, XMODEM-1K receiver, and boot-time verify are now traced; the boot's
split-table "S-box" routine is identified as **CRC16/MODBUS integrity** (not a secret cipher key). The
prefix-decrypt question is **CLOSED by the running-app sector-5 dump (§5.16, `analyze70`)**: there is no
decrypt — the boot strips a `0x402`-byte header and installs `fw[0x402:]` verbatim; the high-entropy
prefix is a discarded header field and the vector SP+reset are `fw[0x402:0x40A]`.

### 5.15 Deeper bootloader RE on the dump (`acq/dump/boot.bin`)  [C trace]

Full Thumb-2 disassembly + call graph via `analyze69.py` (§7): ~11 KB of code in sector 0 (file
`0x0..0x2A24`), 93 functions; boot literal pools are plaintext (§5.13b). Config islands: sector 1
`0x08004000` (160 B config block), sector 2 `0x08008000` (network records), `0xC000`/`0xE638` (8 B each);
sector 4 erased. (Capstone 5.0.9 refuses the `MSR(register)` T1 encoding `f38x 88xx`; `analyze69`
decodes it manually — ARMv7-M SYSm `0x08`=MSP … `0x14`=CONTROL.)

**Storage model — external SPI-NOR is the update pool.** [C] The encoded UPG is staged in an external
SPI-NOR flash at offset `0x100000`+ (the "storage pool"), not internal flash. SPI read = fn `f+0x1ace`
(opcode `0x03`, 24-bit addr + `0x100000`, CS = GPIOE pin 13, SPI4 `0x40013400`, <1 MB). SPI write =
fn `f+0x1b42` (4 KB erase `f+0x1c3e` + 256 B page program `f+0x1bb2`); byte xfer `f+0x1ca4`. The boot
XOR-decodes + CRC-verifies the image **in the SPI pool**, then copies decoded SPI → internal flash
**verbatim** (no re-encoding at install). Internal flash writer `f+0x237c` (erase/program/verify,
`FLASH_KEYR` `0x45670123`/`0xCDEF89AB`, per-word readback).

**Update orchestration.** [C] serial/XMODEM intake → SPI staging → UPG decode → component parse →
install → config rebuild → reset:
- `f+0x1926` launch/update cluster → `f+0x9ae` update wrapper → `f+0x8b2` boot-mode decision (polls
  `f+0x12e0` serial read for `0x55`/`0x75`, magic `0x55AAAA55`/`0x5AA5A55A` @ `0x20002538`, flags
  `0x2000250C`; app verifier `f+0x7b0`) → on update: `f+0x11b4` FLASH option bytes → `f+0x18b6`
  `NVIC_SystemReset` (AIRCR `0xE000ED0C` ← `0x05FA0004`).
- Update command handler `f+0x1108`: magic `"xPAI"` (`0x49415078`) + `0xABCDEF12`, XOR checksum,
  len ≤ `0xE0404`, dispatches flash install `f+0x2168`.
- UPG decode `f+0x1eca` (SPI→SPI): 2-byte XOR (key0/key1, odd bytes ^key1), checks `"XIE2"` @
  staging[`0x3E8`], CRC `f+0x1cc8` (init `0xFFFF`, 22 B header) then a body loop with S-box feedback —
  **residue must = 0** (the standard CRC-append check).
- Install dispatcher `f+0x2168` (parse `f+0x1eca`, install buf+`0x400` via `f+0x206a`); component
  dispatcher `f+0x206a`: MAINARM → `f+0x2490` + config rebuild; BOOTARM → `f+0x24f2` (sector 0);
  certs → `f+0x2024` (limit `0xF8000`). MAINARM install `f+0x2490`: SPI read → internal flash verbatim,
  sector 5 = `0x08020000`, buf `0x20008564`, **no decode at install** (decode already done in the pool).

**UPG component parsing.** [C] fn `f+0x1d68` — TBB 5-state parser; component codes MAINARM=`0x01`,
BOOTARM=`0x0F`, ROOTCERTS=`0x10`, PRIROOT=`0x11`; bounds BOOTARM ≤ `0x4000`, MAINARM ≤ `0xDF000`.
Name strings `f+0x1dd6` `'DATA'`, `0x1df4` `'MAINARM'`, `0x1e04` `'BOOTARM'`, `0x1e14` `'ROOTCERTS'`,
`0x1e24` `'PRIROOT'`; `strcmp` `f+0x1cee`, sanitize whitelist `f+0x1d0e` (table `0x200023E4`).

**XMODEM-1K/CRC receiver.** [C] fn `f+0xc5e`: polls `'C'` (`0x43`) / NAK (`0x15`); SOH (`0x01`) = 128 B,
STX (`0x02`) = 1024 B, EOT (`0x04`), CAN (`0x18`); ACK (`0x06`); state struct `0x20002644`. Serial
init `f+0x1420` @ 230400 (`0x38400`), putchar `f+0xc30`, serial read `f+0x12e0`.

**The "S-box stream-cipher" routine = CRC16/MODBUS integrity (NOT a secret key).** [C] The boot's
split-table feedback routine `f+0x1cc8` uses two 256-byte tables SBOX_A (`0x200021E4`, flash file
`0x26D0`) and SBOX_B (`0x200022E4`, file `0x27D0`). Recurrence: `p = byte ^ crc_lo; crc_lo =
tbl_lo[p] ^ crc_hi; crc_hi = tbl_hi[p]`. **Verified byte-for-byte**: SBOX_A == the CRC16/MODBUS table's
low bytes, SBOX_B == its high bytes, and the split recurrence == standard CRC16/MODBUS (poly `0x8005`
reflected `0xA001`, init `0xFFFF`, refin/refout, xorout 0); the stock firmware's footer + trailer CRCs
reproduce (§5.13). "Residue must = 0" is the standard CRC-append check. This is the **integrity** layer,
not the prefix decryption — there is no secret key in this routine. (Tables are stored split low/high in
flash; scatterload copies them to RAM `0x200021E4`/`0x200022E4`.)

**Boot→app jump — exact sequence.** [C] fn `f+0x119e`: `cpsid i` → `cpsid f` → `bl f+0x2648`
(trampoline `movw/movt ip, 0x080002E1; bx ip` → clock deinit `f+0x2E0`: RCC AHB2/3/APB1/2 = 0,
AHB1ENR = `0x100000`) → `bl f+0x2652` (`ip, 0x08000241; bx ip` → `get_app_reset` `f+0x240`:
`ldr r0, =0x08020000; ldr r0, [r0, #4]; bx lr`) → `bx r0`. **No MSP/VTOR write in the boot** — the app's
own Reset_Handler sets MSP/PSP + VTOR (§5.12). Pre-jump `f+0x1190` writes a BOOT/TOOB handshake magic
`0x424F4F54`/`0x544F4F42` to `0x20000000`. Semihosting exit `f+0x263c` (`bkpt 0xAB`, r0 = `0x18`).

**Boot-time verify.** [C] Two layers: (1) CRC16/MODBUS residue = 0 during UPG decode (`f+0x1cc8`,
above); (2) config-block verifier `f+0x7b0` — additive checksum `f+0x78e` + magic `0x55AA55AA`. Config
block `0x08004000` (160 B): model `KM-CCS2CHAdeMO-1` @ `0x00`, `'MAINARM'` @ `0x20`, version @ `0x40`,
timestamp @ `0x50`, length @ `0x90`, checksum @ `0x94`, magic `0x55AA55AA` @ `0x98`. Config writer
`f+0x2570` (magic `0xADA5AD01`), config-block writer `f+0x21d8` (64 B, default serial `"000000000000"`).
No whole-image hash/signature beyond these CRCs + additive checksum.

**Remaining — RESOLVED by the running-app dump (§5.16, `analyze70`).** The prefix block `0x58–0x3EA`
is high-entropy (7.815) after XOR decode, but the sector-5 dump (`acq/dump/app5.bin`) proves it is a
**discarded header field**: the boot installs `fw[0x402:]` **verbatim** (100% byte match, zero patches),
so the prefix (< `0x402`) is never installed or decrypted. **True link base `0x0801FBFE`** (`fw[0x402]`→
`0x08020000`); the earlier "base A `file 0x400`→`0x08020400`" pointer-table reading was off by `0x402`
and is superseded (§3.4/§5.16). The app startup (`fw[0x40A]`→`0x08020008`) is a **standard ARM C
self-bootstrap** (SP from its own `vector[0]`, zero SRAM+CCM, scatterload, `__main`) — **no boot-patched
literals**; the "`0x44C`/`0x450` placeholders" were a wrong-base artifact (§5.12/§5.16). The boot
constructs **no** app SP/reset constants and the CRC tables have **no second consumer** — consistent
with there being **nothing to decrypt**. **No such
decrypt routine exists in any traced boot path** — static *and* indirect: every `bx`/`blx` register
target was enumerated (reset→`__main`, scatterload `init_fn` dispatch, the app-jump `movw/movt ip; bx ip`
trampolines, printf `bx sl` only); the `blxns r0` @ `f+0x28c4` is scatterload **DATA** mis-disassembled
(file `0x2830..0x29F8`), not code; `f+0xc5e` is confirmed XMODEM-1K intake (its `0xdce` SPI write stores
received blocks). The boot has exactly **one** flash programmer (`f+0x237c`, `FLASH_KEYR` keys only
there) used for verbatim MAINARM/config/BOOTARM installs. So the vector-table/entry setup is **not done
by a boot decrypt** — **because there is no decrypt**: the vector SP+reset are the 8 bytes `fw[0x402:0x40A]`,
installed verbatim as `APP5[0:8]`, and the app self-bootstraps from them. The `SERVICE_DUMP_APP5.UPG`
cave (§5.13i) dumped sector 5 → `acq/dump/app5.bin`; `analyze70` (§5.16) confirms the verbatim install,
the discarded prefix, the true base, and the corrected entry contract. **The prefix-decrypt question is
closed** — the "protection" is the 2-byte XOR + header strip only (§6 confirmed).

### 5.16 Running-app sector-5 dump RESOLVES the prefix question — verbatim install, no cipher  [C ground truth]

`SERVICE_DUMP_APP5.UPG` (§5.13i) dumped the **running** app's sector 5 (`0x08020000..0x08040000`) →
`acq/dump/app5.bin` (131 072 B). Comparing that ground-truth plaintext against `firmware.bin` (the
XOR-decoded stored image) with `analyze70.py` (§7) **definitively closes** the prefix-decrypt hunt and
corrects the link-base / entry-contract model of §3.4/§4.1/§5.12/§5.15:

**Install transform — 100% verbatim, no cipher, no patches.** `APP5[x] == firmware.bin[x + 0x402]` for
**all 131 072 bytes** (100.00%; **zero** mismatch runs). The boot XOR-decodes (2-byte key from `raw[0:2]`),
**strips a `0x402`-byte header**, and copies `fw[0x402:]` **verbatim** to `0x08020000` — no halfword swap,
no stream cipher, no boot-time patch of any installed byte. (The SPI staging pool strips the 2-byte key
prefix, so MAINARM install `f+0x2490` src `SPI[0x400]` = `dec[0x402]` — this reconciles the `0x400` source
offset seen in the boot trace with the `0x402` total header strip.)

**The "encrypted prefix" is DISCARDED.** `fw[0x58:0x3EA]` (914 B, entropy 7.815) lies *inside* the stripped
`0x402`-byte header ⇒ **never installed, never decrypted**. It is a high-entropy header field (encrypted
metadata or decoy), covered only by the recomputable trailer CRC. **There is no prefix cipher** — which is
exactly why the exhaustive static + indirect boot trace (§5.15) found no decrypt routine. The §6 claim
"the protection is a 2-byte XOR" is confirmed correct.

**True link base = `0x0801FBFE`** (`fw[F]` → `0x0801FBFE + F`, i.e. `fw[0x402]`→`0x08020000`,
`fw[0x40A]`→`0x08020008`). The earlier "base A: `fw[0]`→`0x08020000` / `fw[0x400]`→`0x08020400`" (§3.4)
was **off by `0x402`**; the `.rodata` pointer-table test that scored it was flawed. Verified independently
by APP5-internal string pointers (e.g. `0x0802FBB8` → `"[%t]# error! ResponseCod"` @ `fw+0x0FFBA`).

**Corrected entry contract — standard ARM C startup, NO boot-patched literals.**
- Vector `SP = 0x20024D18` (= the scatterload `.bss` end, §5.13b), `reset = 0x08020009` → handler
  `0x08020008` (= `fw[0x40A]`). Like the boot (§5.14), code follows the 2-word SP+reset immediately.
- The "entry header" `fw[0x400:0x40A]` = **[2 discarded bytes `66 F8`][8-byte vector SP+reset
  `18 4D 02 20 09 00 02 08`]**. The "first4 IV `0x4D18F866`" (§5.12) was **never an IV**: `66 F8` is
  discarded and `18 4D` is the SP low halfword; the "6 constant bytes" are the SP high halfword + reset
  vector. These 8 bytes install verbatim as `APP5[0:8]`.
- Reset handler @`0x08020008`: `cpsid i/f` → `ldr r0,=0x08020000; ldr r0,[r0]` (SP from its **own**
  `vector[0]`) → `msr MSP/PSP` → `bl 0x080871D6` (init) → zero-fill **`0xC000` words @`0x20000000`**
  (192 KB SRAM) + **`0x4000` words @`0x10000000`** (64 KB CCM) → `bx 0x08020054` (pool @`APP5+0x50`).
- `0x08020054`: `bl` scatterload (`0x0802005C`) → `bl 0x08020044` → `__main` (`0x080877D2`).
- The "boot-patched literals `0x44C`/`0x450` = `0x0000BBC3`/`0x00550802`" (§5.12) were a **wrong-base
  artifact**: `fw[0x44C]`/`[0x450]` are ordinary app code/data, not patched. The real startup pools are
  `APP5+0x4C` (`=0x08020000`) and `APP5+0x50` (`=0x08020055`), installed verbatim. **The boot patches
  nothing** — a service firmware needs no special startup stub at `0x44C`/`0x450`.

**§5.13(b) "encoded-overlay" corrected — the pack is LOCAL, not whole-image.** The `+2`-packed literal
pools are real **only for the SRAM-copied flash writer** (`fw[0x910AC]`): its pools stay encoded in flash
and are fixed up at SRAM-copy time (e.g. FLASH base `0x40023C00` sits at `fw+0x9118A`, `+2` from the LDR
target `0x91188`). All **in-place** code (FatFs, reset handler, app) is **plaintext verbatim** after the
`0x402` header strip. The earlier whole-image "encoded-overlay" framing and the `0x402` base error came
from over-generalizing this local pack.

**Service-firmware consequence.** A vendor-bootable image needs only: a valid 2-byte XOR key, the `$$`
header, a discarded-prefix field (any bytes — recompute the trailer CRC), the footer (length + CRC), and
`fw[0x402:]` = [8-byte vector SP+reset][app code]. **No stock-prefix reuse or decrypt is required.**
`make_service_upg.py` already preserves `fw[0:0x45E]` verbatim (which includes the vector + startup), so
`SERVICE.UPG` / `SERVICE_DUMP*.UPG` remain valid; the prefix bytes are free to change once the trailer CRC
is re-sealed.

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
> `0x40A`; the header + prefix + footer + startup stub (file `0x000–0x45E`) are **reused verbatim** from a
> stock UPG so the bootloader installs the stock vector SP+reset (`fw[0x402:0x40A]`) verbatim — **no
> prefix key needed** (§5.16: the prefix is discarded, not decrypted); footer + trailer
> are **CRC16/MODBUS**, recomputable, and the app does **not** verify a whole-image checksum.
> `make_service_upg.py` already builds `SERVICE.UPG` (byte-identical stock round-trip, safe) and
> `SERVICE_DUMP.UPG` (bench-confirmed dump cave). The **runtime model is now established (§5.13b):** the
> bootloader decodes the image on first boot after an upgrade and the scatterload relocates **data only**,
> so FatFs runs **in place** and the cave hooks `f_close` with scratch RAM in the scatterload-derived free
> gap. The corrected cave is **bench-CONFIRMED working** (§5.13h): it dumped `BOOT.BIN` (`0x20000` B) to
> USB, acquiring the bootloader non-invasively (`acq/dump/boot.bin`, §5.14) — the original goal. The
> `acq/` read-only SWD kit (§5.7) remains available as an alternative dump path (non-destructive at any RDP
> level; `dump_image` / `stm32flash -r` / `dfu-util -U` at RDP0) but was **not needed**. The prefix-decrypt
> question is **CLOSED (§5.16)**: the running-app dump proves the boot strips a `0x402`-byte header and
> installs `fw[0x402:]` verbatim — no cipher, no boot-patched literals (the deeper boot RE — orchestration,
> app-jump, components, XMODEM, verify — is traced, §5.15). Any **boot-time** code check beyond the CRCs:
> none found beyond CRC + additive checksum (§5.15).

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
  prefix-ciphertext compare (913/914 bytes differ — historically read as a per-image keystream,
  superseded §5.16); `analyze45/46` = capstone
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
  MODBUS-poly CRC32 / subregion CRCs — none; historically inferred IV/nonce, superseded §5.16). The
  reusable `modbus()` table impl lives here.
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
- `analyze69.py` — **full bootloader disassembly + call graph + string/constant xrefs (§5.15)**:
  disassembles the acquired dump's code region (file `0x0..0x4000`) with LDR-literal pool / ADR string /
  BL-target annotation + movw/movt 32-bit constant reconstruction; derives a 93-function map + per-function
  call graph + string-xref table; dumps the non-`0xFF` config islands. Manually decodes the `MSR(register)`
  T1 encoding capstone 5.0.9 rejects (ARMv7-M SYSm). Boot pools are plaintext (§5.13b), so standard
  LDR-literal/ADR resolution applies (no overlay shift). Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze69.py acq/dump/boot.bin > boot69.txt'`.
- `analyze70.py` — **running-app sector-5 dump analysis / ground-truth resolution (§5.16)**: compares the
  acquired `acq/dump/app5.bin` plaintext against `firmware.bin` to prove the install transform —
  `APP5[x] == fw[x+0x402]` for all 128 KB (100%, 0 mismatch runs ⇒ verbatim install, no cipher/swap);
  validates the vector SP+reset (`fw[0x402:0x40A]`), proves the high-entropy prefix (`0x58–0x3EA`) lies
  inside the stripped `0x402` header (discarded, never decrypted), disassembles the app Reset_Handler
  @`0x08020008` with in-place pool resolution (manual MSR decode), and verifies the true link base
  `0x0801FBFE` via internal string pointers. Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze70.py acq/dump/app5.bin firmware.bin'`.
- `analyze71.py` — **correct-base peripheral map + MCU sub-family + RTOS recon (§3.3/§5.1)**: scans
  `firmware.bin` at the ground-truth base `0x0801FBFE` for (1) every raw stored u32 matching a peripheral
  base (HAL keeps bases in rodata **handle tables**, not movw/movt immediates), and (2) code-loaded
  movw/movt + LDR-literal constants; classifies GPIO/CAN/SPI/TIM/ADC/RCC/FLASH/DMA/USB/RNG/SysTick/etc.,
  flags F429/F439-only (LTDC/DMA2D/SAI/FMC) and F437/F439-only (CRYP/HASH) blocks for sub-family
  discrimination, and locates `DBGMCU_IDCODE`/UID/flash-size reads. Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze71.py firmware.bin'`.
- `analyze72.py` — **annotated Thumb-2 app disassembler (§5.8/§5.9)**: disassembles a `firmware.bin` range
  at base `0x0801FBFE+F` with LDR-literal pool values (+ targeted ASCII strings), ADR string targets,
  movw/movt reconstruction, BL/B targets, and manual `MSR(register)` decode. **LDR-literal alignment is
  computed on the runtime PC** (`pca=((rt(a)+4)&~3)-TRUE_BASE`) because the base ≡ 2 (mod 4) — file-offset
  alignment would be off by ±2. Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze72.py firmware.bin START_HEX END_HEX'`.
- `analyze73.py` — **RTOS identification + task-stat/creation trace (§5.1)**: finds uC/OS-II internal-symbol
  strings (`OSRdyTbl`), xrefs the task-stat dump strings (movw/movt + ADR + LDR pools + rodata pointer-table
  fallback), and disassembles the stat dump (tick ÷100 ⇒ 100 Hz) and the named-task creation sites
  (`tcpip_process`/`led_process`/`PDS_PROCESS`). Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze73.py firmware.bin'`.
- `analyze74.py` — **GPIO pin-map decoder (§5.5a/§8.4)**: decodes the board GPIO init @`0x08087010`
  (f+`0x67412`) — per-port MODER/OTYPER/OSPEEDR/PUPDR/ODR/AFR register values extracted from the init
  disassembly (`analyze72.py firmware.bin 0x67400 0x674d0`) — into a per-pin mode/AF/pull/open-drain/
  initial-level table, mapping AF numbers to STM32F427/429 peripheral functions (SPI1/QCA7005 PA5/6/7,
  SPI4/flash PE12/13/14, USART1 PA9/10, USB FS PA11/12, CAN1 PD0/PD1, TIM4_CH1 PD12, ADC analog pins).
  Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze74.py'`.
- `analyze75.py` — **QCA7005 MAC-read MME decoder (§5.9/§8.8a)**: nails the exact MME MMTYPE used to read
  the modem PIB MAC (= EVCCID). Reconstructs the 24-byte request frame from builder `0x08088B48` — pulls
  the 12-byte MAC header template live from `firmware.bin` @`0x080AEC84` (f+`0x8F086`), EtherType
  `0x88E1` (`movw #0xE188`+`strh`, network order), MMV `0`, **MMTYPE `0xA000` (REQ) / `0xA001` (CNF)**,
  payload param `0xB000` + op `'R'`(`0x52`); prints the MMTYPE map (MAC-read `0xA000/01` + SLAC `CM_*`
  `0x6064/65/6A/08/09`) and the call chain (builder → `mme-send` `0x080888CE`; validator `0x08088ADA`;
  poll `0x08088B1E`/retry `0x08088C74`; MAC → SRAM `0x200227E6`). Run:
  `nix-shell -p python3 --run 'python3 analyze75.py'`.
- `analyze76.py` — **SDP security-trigger decoder (§5.9/§8.8b)**: names the config byte that selects TLS
  vs no-TLS in the CCS2 SDP request. Re-derives the naming from `firmware.bin` bytes (no hardcoded
  conclusions): locates the PnC certificate diagnostic strings ("Show Certification Status" / "Root
  certs" / "Pri_root cert" / "Oem cert" / "Contract certs", f+`0x2F2CA`–`0x2F332`), scans the
  config-parser MOVW msg-code loads (`0x8101`–`0x8109`), and disassembles the SDP `tst/beq` decision
  (`0x080204FA`) + accessor `0x08051074` to confirm **security byte = config[+`0x20`] = "Root certs"
  count (msg `0x8101`, ≤5)** and **TLS (`0x10`) iff Root-cert count == 0, else no-TLS (`0x00`)**. Trigger
  = the ISO 15118 PnC root-certificate configuration (flash parser `0x08050E14` ← config block
  `0x001F8010`, magic `0xCEA155E1`; counted by config init `0x08050B94`). Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze76.py'`.
- `analyze77.py` — **ADC-channel→CP/PP signal mapper (§5.5a/§5.5b/§8.4)**: names which ADC channels/pins
  carry CP and PP (and the other analog measurements), re-derived from `firmware.bin` bytes (no hardcoded
  conclusions). Locates the firmware "Hardware Information" dumper label strings (`AD_PP`/`AD_CPD`/`AD_BAT`/
  `CP_DUTY`/`CP_FREQ`/`CP_ST`/`PP_ST`/`+24V`/`HV`, f+`0x2F0FA`–`0x2F1AE`), pairs each dumper BL getter with
  its ADR label, constant-tracks the ADC init (`0x08087B7E`) SQR1/2/3 + CCR + DMA writes to decode the
  regular sequences (ADC1=8×ch8/PB0, ADC2=8×ch9/PB1, ADC3=[1,2,1,2,1,12,1,0]) and result buffers
  (`0x200225E8`/`0x20022628`), and decodes the mV getters' scale to bind each ADCctx field (`0x20000988`) to
  a pin. Confirms **CP DC level = PA0/ADC3_IN0 (`AD_CPD`)**, **PP = PA2/ADC3_IN2 (`AD_PP`)**, PC2=`AD_BAT`,
  PA1=`+24V`, PB0−PB1=`HV`; CP PWM duty/freq = TIM4_CH1/PD12 input-capture (median filter `0x20022688`),
  duty→current by the IEC 61851-1 law (`0x08051E02`), duty→state-char `{'0','1','5','M','N'}` (`'5'`=5%
  digital mode). Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze77.py'`.
- `make_service_upg.py` — **service-UPG builder (§5.13e/f/i)**: implements the cracked format/integrity —
  derive key, XOR-decode, patch app / append cave, re-seal length + both MODBUS CRCs, re-XOR; preserves
  prefix/entry/first4 verbatim. `STOCK -o OUT` (byte-identical round-trip), `--patch OFF:HEX`,
  `--dump-hook` (bootloader-dump cave, bench-confirmed), `--dump-app5` (running-app sector-5 dump cave,
  §5.13i), `--verify-only`. `build_dump_hook` is parameterized (dump base/len/path/magic); defaults
  reproduce the proven boot cave byte-for-byte. Emits `SERVICE.UPG` (safe, stock-equivalent),
  `SERVICE_DUMP.UPG` (bench-confirmed — produced `BOOT.BIN`), `SERVICE_DUMP_APP5.UPG` (§5.13i).
- `SERVICE.UPG` / `SERVICE_DUMP.UPG` / `SERVICE_DUMP_APP5.UPG` — built service images (§5.13e/f/i):
  `SERVICE.UPG` = byte-identical stock round-trip (safe recovery); `SERVICE_DUMP.UPG` = stock + one-shot
  bootloader-dump cave on the in-place `f_close` anchor (598 156 B, valid CRCs, **bench-confirmed working**
  — produced `BOOT.BIN`); `SERVICE_DUMP_APP5.UPG` = same cave retargeted to app sector 5
  (`0x08020000+0x20000` → `0:/APP5.BIN`, magic `0x2003D005`; 598 156 B, valid CRCs, differs from the proven
  boot-dump image in only 9 retarget bytes — §5.13i; **bench-confirmed working** — produced `APP5.BIN`, §5.16).
- `verify_app5.py` (`.qwen/tmp/`) — **independent sector-5 dump-UPG verifier (§5.13i)**: re-derives key,
  re-decodes, recomputes both MODBUS CRCs + length + key-echo, checks prefix/entry/first4 verbatim, the
  `f_close` hook→cave + resume point, scratch addresses, cave-in-sector-9, and the dump base/len/magic/path
  immediates; decisively byte-diffs the decoded image against the bench-proven `SERVICE_DUMP.UPG` and
  asserts only the intended retarget bytes changed. Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 .qwen/tmp/verify_app5.py'`.
- `acq/dump/boot.bin` — **the acquired bootloader** (§5.14): 131 072 B (`0x20000`) dumped non-invasively
  by `SERVICE_DUMP.UPG`, RDP0, plaintext; triaged by `acq/analyze_boot.py` (vector table, reset startup,
  own flash writer, boot→app accessors, XMODEM-1K recovery, UPG component names, ID block).
- `acq/dump/app5.bin` — **the acquired running-app sector 5** (§5.16): 131 072 B (`0x20000`) dumped
  non-invasively by `SERVICE_DUMP_APP5.UPG` (`0x08020000..0x08040000`), ground-truth plaintext; proves the
  boot install is a verbatim copy of `fw[0x402:]` (no prefix cipher) and fixes the true link base
  `0x0801FBFE`; analyzed by `analyze70.py`.
- `REPORT.md` — this document.

## 8. Open questions / next steps

1. **Exact MCU part** — narrowed to **STM32F427/F429, 1 MB flash** (flash-writer’s 12-sector table, §5.6) + 192 KB SRAM + 64 KB CCM. **Peripheral discriminators confirm the narrowing (§3.3, `analyze71`):** no LTDC/DMA2D/SAI1/FMC (⇒ not F429/F439 display variants), no CRYP/HASH (⇒ not F437/F439), RNG present; app reads `DBGMCU_IDCODE` (f+`0x30388`/`0x67802`) + UID (f+`0x68406`) but **not** the flash-size reg. F427/F429 share IDCODE `0x419` ⇒ firmware alone can't separate them. Easiest: **read the MCU top marking** (e.g. `STM32F427VGT6`: V=LQFP100 / Z=LQFP144, G=1 MB) — this also gives the package needed for SWD pin numbers (§5.7). GD32F450/470 clone not fully excluded.
2. **App link base — RESOLVED `0x0801FBFE` (§5.16, ground-truth dump).** `fw[F]`→`0x0801FBFE+F` (`fw[0x402]`→`0x08020000`); the earlier `.rodata` pointer-table "CONFIRMED `0x08020000`" (§3.4) was off by `0x402` and is superseded. The boot→app jump is traced (§5.15: fn `f+0x119e`, `bx` to the app reset vector; **no MSP/VTOR write in the boot** — the app's Reset_Handler @`0x08020008` does it). The prefix-decrypt question is **closed**: the boot installs `fw[0x402:]` verbatim, the prefix is discarded, the vector SP+reset are `fw[0x402:0x40A]` (§5.16); no `BOOT_…UPG` needed.
2b. **Bootloader / update orchestration (bricking-critical)** — **ACQUIRED via the dump cave (2026-11-19, §5.14);** software search had found nothing (2026-11-17). The bootloader is a separate factory component at `0x08000000–0x08020000` (128 KB, sectors 0–4). It is **not in the RAR** (only `MAIN_…UPG`), **not elsewhere in the project**, and **not embedded in the app** — no real vector table; the lone `0x8F652` candidate is a misaligned `.rodata` pointer-table false positive (`analyze25/26`). **Not publicly downloadable:** vendor **Orientrise** (No. 355 Longjin Rd, Changzhou, Jiangsu) ships firmware **contact-only** — `support@orientrise.net` / `sales@orientrise.net`, phone/WhatsApp/WeChat `+86 181 0150 7071`; free firmware on request matched to vehicle/region, **no self-service portal and no `BOOT_…UPG` published**. The nearest open project **`uhi22/ccs32clara` / `osexpert/ccs32clara-chademo`** (Dongguan **Longood** OEM + rebrands EV-Boy / Akyga AK-SC-E18 / EVniculus / Autonlaturit) **explicitly lists Orientrise as NOT compatible** (Longood = STM32F407 + plain `My407ccs2chademo.bin`; Orientrise = F427/F429 + `.UPG`/XOR/encrypted prefix) and does **not** include its own OEM bootloader either — but its README independently corroborates §5.6: *"Firmware update logic is inside the bootloader, so this is not affected by the firmware."* **Acquisition paths:** (a) **email the vendor** for `BOOT_CCS2CHADEMO_1.UPG`; (b) **SWD dump** of `0x08000000` len `0x20000` — **bricking-safe procedure in §5.7** (ESP32-S3 CMSIS-DAP or ST-Link): reading is non-destructive at any RDP level, only an RDP 1→0 *unlock* erases — **never unlock**; probe the first 8 bytes to learn the level first. Once obtained, confirm: who reads USB first, the XOR/prefix decode + any whole-image verify, and any USB/SWD recovery mode. **Kit built (2026-11-18):** path (b) is implemented as the read-only, probe-gated **`acq/` kit** (§5.7 / §7) — SWD (ESP32-S3 CMSIS-DAP + OpenOCD) primary, UART/DFU system-bootloader fallbacks, `analyze_boot.py` triage; software-verified (command names + analyzer smoke-tested). **`boot.bin` acquired 2026-11-19 via the §5.13f dump cave** (no SWD hardware needed) → `acq/dump/boot.bin`, RDP0, triaged in §5.14. **Update orchestration now traced (§5.15):** external-SPI storage pool (`0x100000`+) → serial/XMODEM intake → XOR + CRC16/MODBUS decode in-pool → component parse → verbatim SPI→internal-flash install → config rebuild → reset. Install transform **confirmed by the sector-5 dump (§5.16)**: strip `0x402`-byte header, copy `fw[0x402:]` verbatim — **no prefix-decrypt**.
3. **The prefix block** (`0x58–0x400`) — **RESOLVED: discarded header field (§5.16).** 914 B high-entropy (7.815 after XOR) + plaintext footer `XIE22.00` / **u32 length = filesize−0x404** / u16 CRC `0x2DBE`. The running-app dump proves the boot strips `0x402` bytes and installs `fw[0x402:]` verbatim, so the prefix (< `0x402`) is **never installed or decrypted** — there is **no prefix cipher** (the per-revision difference is per-image header content; the boot's split-table routine is CRC16/MODBUS integrity, §5.15). The footer length/CRC are recomputable. *(The `0x8C400–0x8E600` block is mbedTLS AES/SHA-256 tables, not encrypted data.)*
3b. **Bootloader→app entry contract — RESOLVED (§5.16); integrity CRACKED; service UPG BUILT (§5.12/§5.13).** Reset vector → file `0x40A`→`0x08020008`; file `0x400` = 10-byte entry header (2 discarded bytes + 8-byte vector SP+reset, **not** an IV); startup self-bootstraps MSP/PSP from its own `vector[0]`, zero-fills `.bss`+CCM, scatter-loads — **no boot-patched literals** (§5.16 corrects the `0x44C`/`0x450` claim). Footer u16 + trailer = **CRC16/MODBUS** (recomputable, `analyze52/54`); the app does **not** verify a whole-image checksum. `make_service_upg.py` builds `SERVICE.UPG` (byte-identical stock round-trip, safe) + `SERVICE_DUMP.UPG` (bench-confirmed dump cave on the in-place `f_close` anchor). **Runtime model established (§5.13b):** the bootloader decodes the image on first boot after an upgrade and the scatterload relocates **data only** ⇒ FatFs runs in place; the free-RAM scratch gap is derived from `.bss` end `0x20024D18`. The corrected cave is **bench-CONFIRMED working** (§5.13h): it produced `BOOT.BIN` (`0x20000` B) — the bootloader is acquired (`acq/dump/boot.bin`, §5.14) and the runtime-model gate is closed. **All resolved:** (a) entry = `0x08020054` (stock pool `APP5+0x50`, no patch, §5.16); (b) **boot-time code check — RESOLVED (§5.15):** CRC16/MODBUS residue during decode + config-block additive checksum/magic `0x55AA55AA`, no whole-image hash/signature; (c) deeper bootloader RE — **traced (§5.15)** + install transform **confirmed (§5.16):** app-jump, orchestration + SPI storage model, UPG components, XMODEM-1K, verify; **no prefix-decrypt** (prefix discarded, verbatim install).
4. **Pin map — RESOLVED (§5.5a, `analyze74`); ADC-channel→CP/PP map RESOLVED + NAMED (§5.5b, `analyze77`).**
   The board GPIO init @`0x08087010` (f+`0x67412`) writes
   standard STM32F4 GPIO register values from a literal pool at f+`0x67756` (the earlier "custom packed
   format" guess was wrong — it is just MODER/OTYPER/OSPEEDR/PUPDR/ODR/AFR constants), then locks all pins
   via the helper @`0x08087340`. Decoded: **SPI1/QCA7005 = PA5/6/7 (AF5)**, **SPI4/flash = PE12/13/14 (AF5)**,
   **USART1 = PA9/10 (AF7)**, **USB FS = PA11/12 (AF10)**, **CAN1 = PD0/PD1 (AF9)**, TIM4_CH1 = PD12 (AF2,
   **CP PWM input-capture**); GPIOA–E used (no F–K). **ADC signals named** by the firmware "Hardware
   Information" dumper (`0x0804E92C`): **CP DC level = PA0/ADC3_IN0 (`AD_CPD`)**, **PP = PA2/ADC3_IN2
   (`AD_PP`)**, PC2 = `AD_BAT` (battery, 2:1 divider), PA1 = `+24V` rail, **PB0−PB1 (ADC1+ADC2 dual
   simultaneous) = `HV` DC-link voltage**; CP PWM duty/freq = TIM4_CH1/PD12 capture (not ADC), decoded to
   current by the IEC 61851-1 law (§5.5b). **Remaining:** name the individual GPIO-output
   signals (relay/e-lock/LED/contactor); CAN2 GPIO (no AF9 pins in this
   init — configured elsewhere or CAN1-only board).
5. **CAN IDs & timing** — **LARGELY RESOLVED (§5.8).** Extracted: GB/T J1939 RX/TX/TP ID tables (SA `0x56`/`0xF4`), CHAdeMO H100–H112 + CBMS set, baud table {125,250,500} k @ APB1=42 MHz (SYSCLK 168 MHz **[H]**), CAN init/filter config + driver mailbox-FIFO layer (§5.8.2), and protocol timeouts (1/4/5/6/8 s). **RTOS tick = 100 Hz / 10 ms RESOLVED** (§5.1/§5.8.5). **Remaining:** exact TIM2 busy-delay prescaler + the numeric tick-constants behind the second-valued timeouts; CAN1/CAN2→CHAdeMO/GB/T assignment (**CAN1 pins now confirmed PD0/PD1, §5.5a**; CAN2 GPIO absent from the board init — trace its separate GPIO setup or confirm a CAN1-only board); confirm the runtime-built GB/T IDs (CHM/CTS/CRO/CST/CEM/BRM/BCP/BCS).
6. **QCA7005 firmware** — **RESOLVED: not in this update.** Modem boots from external SPI flash; the MCU is only a SLAC/PLC host (§5.3). For open firmware, use the redistributable Qualcomm blob (open-plc-utils / `qca_spi` ecosystem).
7. **RTOS identity — RESOLVED (§5.1, `analyze73`): uC/OS-II (Micrium), customized.** Identified by the
   internal-symbol debug string `OSRdyTbl` (uC/OS-II ready table). Tick = **100 Hz / 10 ms** (stat dump
   `÷100`); customized TCB accessors + `OSTaskCreateExt`-style wrapper @`0x08088D76`; named tasks
   `tcpip_process` (4 KB stack, prio 10) / `led_process` / `PDS_PROCESS` / `iso1_function_res_process`.
8. **EVCC identity details (§5.9)** — EVCCID = the adapter's **6-byte PLC MAC** (confirmed: SLAC EVHost-MAC, `MAC:` prints, and `SessionSetupReq` all use the same global-struct bytes via thunk `0x080890AE`, which indexes a 48-byte-entry array @SRAM `0x2002390C`, pointer at `+0x2C`). **(a) MAC-read MMTYPE RESOLVED** (`analyze75`): chain SLAC banner → `0x0802156C` → `0x08088C10` (mutex + PC5 reset) → `0x08088B94` (QCA7005 SPI signature `0xAA55`@reg`0x1A00`) → `0x08088A0E` (SPI reg init `0x1200=0xC5B`/`0xC00=0x447`/`0xD00=0x41`); then the MAC-read MME = **vendor-specific MMTYPE `0xA000` (REQ) / `0xA001` (CNF)**, MMV `0`, EtherType `0x88E1`, payload param `0xB000` + op `'R'`(`0x52`, Read). Builder `0x08088B48` (12-byte header template `0x080AEC84`, dest = QCA7005 **default** MAC `00:B0:52:00:00:01`; EtherType via `movw #0xE188`+`strh`), validator `0x08088ADA` (CNF `0xA001`, done-marker `0x55`), poll `0x08088B1E` / retry `0x08088C74`; 6-byte MAC → SRAM `0x200227E6` (accessor `0x08088CAC`). SLAC `CM_*` MMTYPEs also decoded: `0x6064/65` `CM_SLAC_PARM`, `0x606A` `CM_START_ATTEN_CHAR`, `0x6008/09` `CM_SET_KEY` (decoder `0x080214D6`). **(b) SDP security trigger RESOLVED + NAMED (`analyze76`):** security = (config byte @SRAM `0x20018A0C` == 0) ? TLS : no-TLS, via accessor `0x08051074` (config struct `0x200189EC`). The byte is the **"Root certs" count** — named by the firmware diagnostic dumper `0x0804EB5C` ("Show Certification Status", f+`0x2F2CA`): config[+`0x20`] = Root certs (msg-code `0x8101`, ≤5), [+`0x21`] = Pri_root cert (`0x8102`), [+`0x22`] = Oem cert (`0x8105`), [+`0x23`] = Contract certs (`0x8109`, 32 B). Flash parser `0x08050E14` copies msg-`0x8101` entries from the PnC cert config block @`0x001F8010` (magic `0xCEA155E1`) into a 5-slot array; config init `0x08050B94` counts them. **Trigger = the ISO 15118 PnC root-certificate configuration** (TLS iff Root-cert count == 0), a service-config property — not DIN-vs-ISO and not per-session. The msg-code set is `0x8101`–`0x8109` (the earlier `0x810D` was a conflation of two functions; no such code).
9. **Device provenance (§5.10)** — vendor **disavows the unit as a clone**; firmware nameplate = **`KM-CCS2CHAdeMO-1`** / `CCS2GBT` with CATL/CAMA BMS code. Identify the **"KM" OEM**: web search was unavailable (2026-11-18, retry); decode the ID-block fields `F$K$N$T$2005$TY/VR$…` (f+0x090df0); check enclosure/label markings and the `SER:202406180463` date-code convention against other units. The USB log **proves the unit runs C009 = `firmware.bin`** (§5.10), so all RE findings apply to this hardware regardless of brand. MAC OUIs are IEEE-RA reference values — not a maker fingerprint.