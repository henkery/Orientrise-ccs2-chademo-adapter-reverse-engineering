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

GPIO outputs — **signal names RESOLVED (§5.5c, `analyze78`)**: **PreChargeRELAY = PB10/PB11**,
**BatteryPower = PD8**, **BatteryCharge = PC9**, **e-lock motor = PD3/PE4** (pulse-train drive),
**CHAdeMO-side enables = PE7/PE8**. Status-feedback inputs: **KEY_LOCK = PD10** (e-lock), **PD9** (e-lock
position), **PE10** (CHAdeMO), **PB12 = PLC D_LINK** (QCA7005 link), **PC8** (PreChargeRELAY). The PB15
output primitive is unreferenced (unused); PA4/PB14/PC5/PE11/PE15 are not tied to a named driver. PA13/PA14
left as inputs (SWD not claimed by the app). **CAN2 has no AF9 pins in this init** (PB5/PB6/PB13 left as
inputs; PB12 is the PLC D_LINK input) — **resolved (`analyze79`, §5.8.2): this is a CAN1-only board**; CAN2
is unwired generic-HAL scaffolding, and CAN1 carries both CHAdeMO and GB/T. Full per-pin mode/AF/pull/open-drain/initial-level
table: `analyze74.py`.

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

### 5.5c GPIO-output signal map — DECODED + NAMED (`analyze78`)  [C]
**RESOLVED (§8.4).** The relay / e-lock / contactor drives are a cluster of tiny **push-less GPIO
primitives** @`0x080879EC`–`0x08087AF8` (f+`0x67DEE`–`0x67EFA`): each writes one pin (or a paired set) via
`BSRR` (+`0x18`, set-mask | reset-mask<<16) or reads one pin via `IDR` (+`0x10`) / `ODR` (+`0x14`) + `ubfx`.
Xref-ing each primitive to its BL callers and the callers' enclosing-function ADR naming strings binds
pin → signal:

| signal | pin(s) | drive primitive | feedback | naming evidence |
|---|---|---|---|---|
| **PreChargeRELAY** | **PB10 + PB11** | `0x08087A84` | PC8 (`0x08087AE0`, active-low) + PB10 readback | `_PreChargeRELAY %s[v=%.3u]` / `can't open/close` |
| **BatteryPower** | **PD8** | `0x08087A3C` | PD8 readback `0x08087A4E` | `BatteryPower %s`; interlock clears PC9 first |
| **BatteryCharge** | **PC9** | `0x08087AC0` (active-low) | PC9 ODR readback `0x08087AD2` | `BatteryCharge %s` |
| **e-lock motor** | **PD3 + PE4** | `0x08087A58` (active-low, paired) | PD9 (`0x08087A32`) + KEY_LOCK PD10 | fn-ptr registered into E_LOCK state machine |
| **CHAdeMO enable** | **PE7 / PE8** | `0x080879EC` / `0x080879FE` | — (write-only) | set in CHAdeMO H100/H102 after a 0.5 s delay |
| **CHAdeMO status** | **PE10** (input, active-low) | — | `0x08087A24` | CHAdeMO H100/H101/H102 + stop-charger |
| **PLC D_LINK** | **PB12** (input) | — | `0x08087AA6` | SLAC `D_LINK_DISCONNECTED`/`RESTORED`, `AVLN` |

**e-lock motor drive mechanism.** `E_LOCK` is a uC/OS-II task (entry `0x080515AB`, created `0x080516B0`,
prio 1). Its periodic tick — registered as the **misnamed `led_process`** process via `0x08089858`
(callback `0x08051718`) — runs a **shift-register pulse driver** `0x080517C6`: a 16-bit pattern (struct+`0x4`)
is shifted out one bit per 100 Hz tick (16 ticks = 160 ms) and tail-called (`bx ip`) through the registered
GPIO driver `0x08087A58` = **PD3+PE4** (both pins driven with the same inverted bit). The pattern is selected
by motor profile from a **12-entry u16 table @`0x080AB604`** (`0x08051826`): e.g. `0xFFFF`=continuous,
`0x00FF`=8-on/8-off, `0x7777`=3-on/1-off, `0x0000`=off — matching the lock-motor profile strings
(`H12`/`JH12`/`JH24`/`A12`/`IE12`/`A24`/`IE24`/`ELS5_V12M`, f+`0x90060`+). Lock status is read on
**KEY_LOCK = PD10** (`0x08087AEE`, the dumper's `KEY_LOCK` row) and **PD9** (`0x08087A32`). The `ELOCK=`
diagnostic dispatch (`0x080526FE`, `tbb`) sets software command flags in struct `0x200003D8` (via
`0x080231CA`/`0x080231F2`/…) that the task acts on — it does **not** drive GPIO directly. **PB15** has a
write primitive (`0x08087AB0`) but **zero references** (unused output); the `led_process` label is the e-lock
tick, not a separate LED block (LED drive pins not yet tied to a named driver). Re-derived from bytes by
`analyze78.py`.

**Drive-pin ACTIVE levels + SAFE boot state (`analyze86`).** Decoding each C013 drive primitive's BSRR
logic (low16 = SET→HIGH, high16 = RESET→LOW) fixes the active level and the de-asserted **SAFE** level a
custom app must drive at boot so every contactor stays open / no HV appears:

| signal | pin(s) | active | SAFE (de-asserted) |
|---|---|---|---|
| CHAdeMO enable d1 / d2 | PE7 / PE8 | HIGH (`cmd<<7/8` SET) | **LOW** (disabled) |
| BatteryPower (inner contactor) | PD8 | HIGH (`cmd<<8` SET) | **LOW** (open) |
| PreChargeRELAY | PB10 + PB11 | HIGH (`cmd<<10/11` SET) | **LOW** (open) |
| BatteryCharge | PC9 | LOW (`bics` inverted → RESET) | **HIGH** (charge off) |
| e-lock motor | PD3 + PE4 | LOW (`bics` inverted → RESET) | **HIGH** (motor off) |

The PreChargeRELAY reset masks use an address-bit trick (`lsls r2, r1, #0x10/0x11` with r1 = GPIOB base
`0x40020400`, whose bit10 survives → `(1<<10/11)<<16`); the SET shift is the reliable pin indicator.
`custom_fw/src/gpio.c` pre-loads these SAFE levels via BSRR while the pins are still reset-state inputs,
then switches MODER to output — glitch-free, never driving an asserted level. Re-derived by `analyze86.py`.

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

### 5.8 CAN bus deep-dive — identifiers, baud rates, timing  [C]

**CAN1-only board (`analyze79`).** The adapter wires a single vehicle-side CAN controller — STM32 bxCAN
**CAN1** `0x40006400` on **PD0/PD1 (AF9)** — and runs **both** protocols on it: **CHAdeMO** (11-bit IDs,
500 kbit/s) and **GB/T 27930** (29-bit SAE J1939 IDs, 250 kbit/s), one active at a time (whichever vehicle
is attached). **CAN2** `0x40006800` exists only in the generic bxCAN HAL (handle-table entry + stop thunk +
filter bank 14 via `CAN2SB=14`) but is **unwired**: no CAN2 AF9 GPIO in the board init, no CAN2 service
task, and its base is loaded at a single site (the unreferenced stop thunk, §5.8.2). The protocol layer
reaches the peripheral through a **base-pointer + register-offset** handle table at `0x67B74` (12-byte
stride, 2-mod-4 aligned — a step-4 literal-xref scan misses it); the HAL/driver also loads the bases as
LDR-literals at **7 CAN1 sites vs 1 CAN2 site** (`analyze79` part 2).

#### 5.8.1 Baud rates & bit timing  [C]

A **3-entry BTR (bit-timing) lookup table** sits in the boot config block at file `0x08F062`
(2-byte-aligned, immediately before the default-IP word `192.168.1.1` = `0x0101A8C0` @ `0x08F06E`).
Decoding each word as an STM32 `CAN_BTR` (`BRP[9:0]=psc−1`, `TS1[19:16]=BS1−1`, `TS2[22:20]=BS2−1`,
`SJW[25:24]=SJW−1`) yields **exactly {125, 250, 500} kbit/s only when APB1 = 42 MHz**:

| BTR word | psc | BS1 | BS2 | tq/bit | baud @ 42 MHz | sample point |
|---|---|---|---|---|---|---|
| `0x002B0014` | 21 | 12 | 3 | 16 | **125 kbit/s** | 81.25 % |
| `0x00050014` | 21 | 6 | 1 | 8 | **250 kbit/s** | 87.5 % |
| `0x00270006` | 7 | 8 | 3 | 12 | **500 kbit/s** | 75 % |

- ⇒ **APB1 = 42 MHz ⇒ SYSCLK = 168 MHz** — **CONFIRMED from RCC (`analyze79` part 1, was [H]).** The
  clock-config function @`0x080872BA` (f+`0x676BC`) writes `PLLCFGR = 0x07402A04` (PLLM=4, PLLN=168,
  PLLP=2, PLLQ=7, PLLSRC=HSE ⇒ HSE 8 MHz /4 ×168 /2 = **168 MHz**), `CFGR = 0x80209400` (HPRE=/1,
  **PPRE1=/4 ⇒ APB1=42 MHz**, PPRE2=/2 ⇒ APB2=84 MHz), and `FLASH_ACR = 0x705` (5 wait-states + I/D-cache
  + prefetch, correct for 168 MHz @ 3.3 V). APB1 timer clock = 84 MHz (×2 when PPRE1>1). The 42 MHz APB1
  reproduces the {125,250,500} kbit/s BTR table exactly.
- CAN init **indexes this table by a baud selector** (range 1–4, **default 3 → 500 kbit/s**). Menu
  strings **`CANBAUD1`** / **`CANBAUD2`** (`0x02EC2E` / `0x02EC3E`) make each bus's rate
  user-configurable. **CHAdeMO = 500 k, GB/T = 250 k** (standard). The config block is copied to RAM at
  boot (no live flash pointer found).
- **CAN1/CAN2 → CHAdeMO/GB/T assignment — RESOLVED (`analyze79`, §5.8.2):** **CAN1-only board.** CAN1 =
  PD0/PD1 (AF9) is the only wired controller and carries **both** protocols (11-bit CHAdeMO + 29-bit GB/T),
  split by the IDE bit in a single frame dispatch; CAN2 is present in the generic HAL but unwired.

#### 5.8.2 CAN controller init  [C]

Generic CAN-open @ `0x08087482` (f+`0x67884`; HAL-style, base passed in `r0`, a `tbb` dispatcher on the
handle mode byte `+0xF08`). The init arm writes:
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

**CAN1-only assignment + protocol dispatch (`analyze79` parts 2–5):** the init arm's filter-bank setup
(`FMR/FM1R/FS1R/FFA1R/FA1R` at `CAN1+0x200`) is guarded by `cmp r0,r5; bne` @`0x08087502` where
`r5 = 0x40006400` (loaded at the function top) — bxCAN shares all filter registers through the CAN1 base,
with `CAN2SB` splitting the banks, so a CAN2 open skips this block. Only **one** CAN service task exists:
**`CAN1_REC`** (created @`0x08052820`, entry `0x080527DB`), which waits on CAN1's cfg event queue
`0x20000978` (== the CAN1 handle cfg word @f+`0x67B7A`) via the event-wait `0x080893EA`, polls RX with
`0x080875F0`, and dispatches frames through `0x080524FE`. There is **no `CAN2_REC` task**. The frame
dispatch `0x080524FE` splits on the **IDE bit** — `ubfx r0,r5,#0x14,#4; cmp #0xA; beq` selects the 29-bit
extended path → **GB/T 27930 J1939** (PF compares `#0x14/0x1A/0x1C/0x1E`), else the 11-bit standard path →
**CHAdeMO** handlers (`0x08052426`/`0x08052958`). Thus CAN1 carries both protocols, one active at a time.
**CAN2 is unwired:** its base `0x40006800` is loaded at exactly one site — the stop thunk `0x08087476`,
which has **0 BL callers** — and there is no CAN2 AF9 GPIO in the board init (§5.5a). The CAN2 handle/filter
bank 14 are vestigial generic-HAL scaffolding, never serviced.

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
- **Busy-delay timebase CONFIRMED [C, `analyze84`, §5.20]:** TIM2 tick = 10 µs (100 kHz) — PSC=839
  (84 MHz/840), `ARR=0xFFFF` free-running, independent of the OS tick (busy-unit ≈ 1 µs ⇒ the earlier
  inference was correct). TIM1 (PSC=1679, 168 MHz/1680) and TIM3 (PSC=839) are the same 100 kHz timebase.
  The timer @ `0x6847A` with PSC=83/ARR=1110 is a ~1.111 ms PWM, *not* the free-running TIM2 timebase.
  TIM2's base is computed (TIM1<<14), not LDR-literal loaded (§5.20). The numeric tick-constants behind
  the second-valued timeouts are extracted in §5.17/§5.20/§5.21 (10 ms units: 250/424/125/1525).

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

### 5.17 CHAdeMO charge state machine — DECODED (C013 improved logic, `analyze80`)  [C]

The vehicle-side charge controller for the CCS2-EVSE ↔ CHAdeMO-vehicle path is the **`CHAdeMO stm`**
state machine (C013 code region f+`0x21A6E`–`0x2EA74` / runtime `0x0804166C`–`0x0804E672`, ~53 KB,
387 log format strings). Its context struct `p` keeps the **state in the halfword `p->state` @ `+0x02`**;
every transition is a `strh rX,[p,#2]` (p in `r4`). `analyze80.py` re-derives the skeleton from bytes:
it xrefs every `CHAdeMO stm` log string (full NUL-bounded start incl. the `[%t]#` prefix), parses the
numbered case labels, and extracts each `p->state` write with its decoded next-state immediate.

**Safe-charge sequence (state → next, from the decoded transitions):**

| phase | states | action / guard |
|---|---|---|
| plug-in / authorize | … → 13 | `GET_AD_CPD` connector plug-in; DIN70121 / ISO15118 EVSE authorized |
| CableCheck | 13 → 14 | isolation check (`EVSEIsolationStatus`), 50 s timeout; `SET_CSS1 d1 ON` on finish |
| ChargeParameterDiscovery | 14 → 15 | send CML/CTS, 65 s timeout; H102.`VehicleChargingEnabled`, 8 s from d1=ON |
| precharge start | 15 → 16 | `Switch(d2)=ON`, 8 s (configurable) for EV contactor; H102.`VehicleStatus` |
| EV contactor / current req | 16 → 17 | 4 s after d2=ON; H102.`ChargingCurrentRequest` > 0 A |
| **precharge voltage-match** | **17 → 18** (or → 450 wait) | **the engagement guard below** — C013 stalls here until the EVSE reaches target |
| precharge relay close | 18/19 → 20 | `set_precharge_relay`, wait `TargetBatteryVoltage`; 1 s `set_precharge_relay failed!terminate` |
| current demand | 20 → 30 | send H108/H109 (`get_hv`, `get_precharge_relay`); `CurrentDemand phase`, `setpara_maxevsecurrent` |
| stop (normal/abnormal) | 30 → 31/50/60/40 | stop by vehicle (normal→50, abnormal→60) / by charger (→40); remaining-time 0 → 50 |
| contactor open / de-energize | 31 → 32 → 33 → 34 → 35 | wait switchK off (4 s); output voltage < 10 V → `energizing_state=0` |
| shutdown / unlock | 41…44 → 51 → 52 → 53 → 61 → 62 | H109.5.4=1 (welding/contactor check); `phase_cnt>=200` stop-control (61), `>=350` unlock (62) |
| e-lock unlock / end | 62 → 650/652 → 91/300 | `STM_EVCC_UNLOCK_ACTION_STEP1/2/3` (unlock-failed-3-times guard); close A+; charging end |

**Special state codes:** `300 (0x12C)` = `STM_TIMEOUT_STOP_CHARGER_TRIGGERED`, `450 (0x1C2)` = common
wait/error pending state, `600 (0x258)` = `notify_bms_shutdown`, `650 (0x28A)`/`652 (0x28C)` = unlock/stop
action steps. Per-message CAN watchdogs: H100/H101/H102 each **1 s**, whole-bus **15 s** (C013).

**State-17 precharge voltage-match (engagement) guard — the safety-critical check C013 fixes**
(`0x0804AF08`–`0x0804AF30`): with `outvol = p[+0x16]` (EVSE output voltage) and `ress_vol` in `r10`
(car-side residual/battery voltage), the guard requires `[r6+0x23F]==1`, an isolation word `==4`,
**`outvol+10 >= ress_vol` AND `outvol-5 <= ress_vol`** (i.e. `outvol ∈ [ress_vol−10, ress_vol+5]`), and a
counter `p[+0x0A] >= 0xFA (250)`. On match it clears the counters and sets `p->state=18`; otherwise it
stalls in the wait state (450, `Precharge,wait out[%lu]reach ress_vol`). **C009** closed the precharge
relay as soon as `outvol ≈ ress_vol` without waiting for the EVSE to ramp to target → the car held ~1–2 A
and raised H102 `VoltageDeviation`+`CurrentDeviation` → emergency abort (§5.11); **C013** waits for the
EVSE output to actually reach the battery voltage before mating the contactors, then ramps current.

**Safety-stop / abort paths (from the log strings):** `get_evcc_hw_fault` (+ `get_key_lock` error),
`h102_status error`, `E-lock Failed!go to shutdown`, CableCheck `EVSEIsolationStatus` error / 50 s timeout,
`Precharge timeout` / `PreChargeRes t>=tout`, `set_precharge_relay failed!terminate`, CAN 15 s timeout,
`bms_error_stop` (`data_tmout`), `charging_system_error` / `charger_error`, `emergency_flag==1` (stop by
charger), `SYNCH_POWERDELIVERY_ERR`, and the unlock-failed-3-times guard. These are the interlocks a
custom charge controller must preserve.

*(Method note: `analyze80`'s per-transition text labels are a nearest-preceding-log-string heuristic and
can be approximate; the `p->state` values, code offsets, and the engagement-guard immediates are exact.
The GB/T `GBT stm` and ISO15118 `iso1_…` machines are separate controllers — `CurrentDemand phase,BCL 1s
timeout` lives in the GBT stm; their full maps are pending.)*

**custom_fw replica (inert shadow controller).** `custom_fw/src/charge_stm.c` reproduces the safe-charge
sequence (states 13→14→15→16→17→18→19→20→30 + a stop/shutdown skeleton 31→32→33→34→35→50, error states
300/450/600) as a **shadow** controller: it evaluates the guards/interlocks and *records* the power action
each state would drive (`STM_ACT_*`, mirroring §5.5c) but **executes no GPIO** — the asserted drive is the
last gated layer. The **state-17 engagement guard is byte-exact** (`charge_stm_engage_ok`): `flag==1 &&
isolation==4 && outvol+10>=ress_vol && outvol-5<=ress_vol` (unsigned 32-bit on zero-extended halfwords,
window `outvol ∈ [ress_vol−10, ress_vol+5]`) `&& dwell counter>=250`; state-17 wait counter times out at
424. It is host-unit-tested (`custom_fw/test_charge_stm.c`, 47 checks: window bounds, dwell/isolation/flag
thresholds, unsigned wrap, sequence walk/stall/engagement, interlocks, and the C009 mismatch never-engages
case). **Interlocks:** whole-bus 1525-tick watchdog→450, per-message 100-tick, H102 byte4/5 fault→300,
`emergency_flag`→40, bms/hw_fault→600, CurrentDemand requires isolation==3. **EVSE-side handshake inputs**
(isolation / precharge_flag `[r6+0x23F]` / plug_in / cablecheck_fin / chgparam_ok / ev_contactor /
precharge_relay) are parameterized and **safe-stubbed (0)** until the CCS2 PLC/DIN subsystem is built, so
the machine holds in the early states and the engagement guard cannot pass. State/interlock/engage/action
are published as SWD-readable `stm_*` globals; `outvol` is the measured `get_hv()/10`.

#### Power-stage drive + HV ADC front-end (C013, `analyze81`)  [C]

The state-machine actions drive the **same physical pins as C009** (§5.5c) — the board is hardware-
invariant; C013 only shifts the code. `analyze81.py` re-locates the GPIO primitive cluster in C013 at
**`0x08088400`+** (f+`0x68802`+, vs C009 `0x080879FE`) and re-binds each write primitive to its naming
strings via BL-callers → enclosing-function ADR/LDR:

| signal | pin(s) | C013 drive primitive | callers → naming |
|---|---|---|---|
| **CHAdeMO enables (d1/d2)** | **PE7 / PE8** | `0x08088400` / `0x08088412` | 21 / 14 → CHAdeMO×7 each |
| **BatteryPower** (inner contactor) | **PD8** | `0x08088450` | 4 → BatteryPower |
| **e-lock motor** | **PD3 + PE4** (active-low) | `0x0808846C` | 3 → (E_LOCK fn-ptr, no naming str) |
| **PreChargeRELAY** | **PB10 + PB11** | `0x08088498` | 5 → PreChargeRELAY×3 |
| **BatteryCharge** | **PC9** (active-low) | `0x080884D4` | 6 → BatteryPower×1, BatteryCharge×1 |
| (unused) | PB15 | `0x080884C4` | 0 callers |

Feedback inputs re-confirmed: PE10 (CHAdeMO status, active-low), PD9 (e-lock position), PD8/PB10/PC9
readback, PC8 (PreChargeRELAY, active-low), PD10 (KEY_LOCK), PB12 (PLC D_LINK), PB8 (active-low). So
`set_precharge_relay` → PB10/PB11, `close inner relay`/BatteryPower → PD8 (interlock clears PC9 first),
BatteryCharge → PC9, `SET_CSS1(d1)`/`SET_CSS2(d2)` → PE7/PE8, e-lock unlock → PD3/PE4 pulse train.

**HV ADC front-end + calibration.** The HV DC-link voltage (`get_hv`, used by the state-17 engagement
guard and H108/H109) is measured **ADC1+ADC2 dual simultaneous** (PB0/PB1). The ADC init/calibration
function (f+`0x68986` / `0x08088584`) configures ADC1 (`0x40012000`), ADC2 (`0x40012100`), ADC3
(`0x40012200`), ADC12_COMMON (`0x40012300`) and DMA2 (`0x40026400`), then computes **Vrefint-referenced
scale factors** by `udiv`: it calls the Vrefint read `0x080889C4` (raw → `calibration_struct[+2]`), then
`162981000 (0x09B6E488) / raw → calibration_struct[+4]` and `180180000 (0x0ABD5420) / raw →
calibration_struct[+6]` (halfword factors), with **calibration struct = `0x200009C0`**. DMA2 streams the
dual-ADC results to buffer `0x20022640`; the scan/range-check consumer (`0x0808876A`) reads the packed
halfwords and compares them against the two factors. Additional per-channel scaling constants appear in
the init cluster (`0x04924924`, `0x24924924`, `0x00742108`, `0x10842108`, `0x1E000001`, `0x0002A006` —
ADC SMPR/CR register writes). `get_hv` is only a log substring (no standalone xref); the full
**raw→volts getter** that consumes these factors is still pending (roadmap D). The engagement guard
(§5.17) operates on the already-scaled `outvol`/`ress_vol`. Re-derived from C013 bytes by `analyze81.py`.

### 5.18 CHAdeMO message layer + output control law — DECODED (C013, `analyze82`)  [C]

The adapter acts as the **CHAdeMO charger** toward the vehicle, so it *receives* H100/H101/H102
(vehicle status + current/voltage request) and *transmits* the periodic **H108/H109** charger-status
messages. `analyze82.py` re-derives the transmit half from bytes by scanning for the CAN-ID store
pattern (`mov r1,#ID; str r1,[rX,#0x60]`) and decoding each sender's payload packing.

**Periodic tick dispatcher.** The `CHAdeMO stm` tick (the state-30 CurrentDemand handler region,
f+`0x28C56`+) calls four message functions on a modulo schedule of the tick counter `p[+4]`:
`udiv #10 / mls` (every 10th tick) gates the H108/H109 build+send quartet
`0x0803C95C → 0x0803CB36 → 0x0803C9B8 → 0x0803CBDC`; `cmp #0x14 (20)` advances `p->state`;
`cmp #0x64 (100)` is a timeout. This is the `"CurrentDemand phase, every n minute adjusts current
limintation"` behavior — the output command is recomputed periodically, not continuously.

**H108 (CAN ID `0x108`) — charger output status.** Build `0x0803C95C`, send `0x0803CB36`:

| CAN byte | source | note |
|---|---|---|
| 0 | `p[+0x210]` | status byte (set = 1 by the build) |
| 1–2 | `p[+0x212]` (lo, hi>>8) | **the /1000-scaled output value, clamped to 450 (0x1C2)** |
| 3 | `p[+0x214]` | |
| 4–5 | `p[+0x216]` (lo, hi>>8) | |
| 6 | `p[+0x218]` | |
| 7 | `p[+0x219]` | |

The build reads EVSE-side measurements from a source struct at +`0x3D08/0x3D0A/0x3D22/0x3D30` via the
converter `0x0804E786`, computes `value × raw / 1000` (`muls` then `udiv` by a register loaded `#0x3E8`),
and **clamps the result to 450** (`mov r0,#0x1C2; cmp r1,r0; blo; mov r1,r0`) before storing `p[+0x212]`.

**H109 (CAN ID `0x109`) — charger status / remaining time.** Build `0x0803C9B8`, send `0x0803CBDC`:

| CAN byte | source | note |
|---|---|---|
| 0 | `p[+0x220]` | status (build sets = 3) |
| 1–2 | `p[+0x222]` (lo, hi>>8) | /1000-scaled value |
| 3 | `p[+0x224]` | /1000-scaled value (periodic-gated) |
| 4 | `p[+0x225]` | |
| 5 | `p[+0x226]` | **low 6 bits bit-reversed on the wire** (`ubfx` per-bit + `orr` re-pack) |
| 6 | `p[+0x227]` | |
| 7 | `p[+0x228]` | |

The H109 build is **state-gated**: it only updates on every 10th tick (`bl 0x08052770` = `get_hv`, the
HV-voltage getter — see §5.21; `sdiv #10`, `cbnz` → zero the value otherwise) and only within the
CurrentDemand/stop state ranges
(`p->state ∈ {0x20–0x23, 0x29–0x2C, 0x33–0x34, 0x1C2–0x1C3, 0x28A–0x28C}`), else the output is held/zeroed.

**CAN TX path (both senders).** `memset(buf,0,8)` via `0x080882CE`; the 8-byte buffer pointer is
`p[+0x25C]`; the CAN ID is written to `0x200007E0`; a mutex `0x200007E8` is taken (`0x08089D4C`) /
given (`0x08089DB8`) around the pack; transmit is via the **fn-ptr `p[+0x270]`** (`blx`) then the CAN1
transmit `0x08052EE2(ID, buf)` (the same CAN1-only layer as §5.8). A flag `p[+0x49]` triggers an
immediate re-send.

**Control-law summary (safe-charge report half).** The adapter reports its DC-link output to the vehicle
as H108/H109, scaling the EVSE-side measurement by `/1000` and **clamping the primary output value to
450**; the command is refreshed periodically (every 10 ticks) and gated by charge state. Together with
the state-17 voltage-engagement guard (§5.17) this forms the safe operating envelope: mate contactors
only when `outvol ∈ [ress_vol−10, ress_vol+5]`, then ramp/limit the reported output. *(Field physical
meaning — voltage vs current vs remaining-time — follows the CHAdeMO H108/H109 spec; the byte packing,
IDs, /1000 scaling, 450 clamp, bit-reversal and TX path above are byte-derived. The vehicle-request parse
H100/H101/H102 → output-current setpoint and the full `get_hv` raw→volts law are now decoded in §5.21
(`analyze85`); the timebase that clocks these periodic updates is in §5.20 (`analyze84`).)*
Re-derived from C013 bytes by `analyze82.py`.

**RX parse — H100/H101/H102 CAN-byte → field (`analyze87`).** The receive side is byte-derived from
the C013 CHAdeMO parse handler `0x0803BB72` (dispatched by `cmp r0,#0x102`). The RX frame buffer
(stm context `p[+0x260]`) carries a **4-byte ID header** (word0 = ID/RTR/IDE packed, §5.8.2 mailbox
layout), so **CAN data byte N = buffer offset 4+N**. Halfwords are read **little-endian** by helper
`0x08050976` (`ldrb r1,[r0,#1]; ldrb r0,[r0]; add r0,r0,r1,lsl#8` ⇒ `b0 | b1<<8`).

| msg | CAN byte(s) | stm-context field | meaning |
|---|---|---|---|
| **H102** `0x102` | byte0 | `p[+0x1d8]` | status byte |
| | byte1–2 (LE) | `p[+0x1da]` | **TargetBatteryVoltage** (V) |
| | byte3 | `p[+0x1dc]` | **ChargingCurrentRequest** (A) |
| | byte4 | `p[+0x1dd]` | fault byte (1:1 bit copy) |
| | byte5 | `p[+0x1de]` | fault byte |
| **H101** `0x101` | byte0 / byte1 | `p[+0x1ba]` / `p[+0x1bb]` | status bytes |
| | byte2–3 / byte4–5 (LE) | `p[+0x1bc]` / `p[+0x1be]` | halfwords |
| | byte6 / byte7 | `p[+0x1c0]` / `p[+0x1c1]` | status bytes |
| **H100** `0x100` | byte0..7 | low offsets `p[+0x5..0xc]` | vehicle status (max battery V etc.) |

This matches §5.8.4 "102.4/102.5 = byte4/5 fault". **Reconciliation:** the §5.10 raw-frame note
tentatively placed ChargingCurrentRequest at H102 byte0; the byte-derived C013 parse places it at
**byte3** (byte0 is the status byte) — the parse code is authoritative. `custom_fw/src/chademo.c`
reproduces this map. Re-derived from C013 bytes by `analyze87.py`.

### 5.19 Custom-firmware build / flash / stock-recovery recipe — CONSOLIDATED (`analyze83`)  [C layout · H build]

This consolidates the bricking-critical layout (§3.3/§3.4/§5.6/§5.12/§5.13/§5.16) into an actionable
recipe for a custom app that the **stock bootloader will launch** and that can be **flashed back to
stock**. `analyze83.py` re-derives the layout from the firmware bytes and emits a linker script.

**Flash map — byte-derived from the flash-writer's own 12-entry tables** (sizes @file `0x9119E`,
start-offsets @`0x911CE`; 1 MB, STM32F427/F429 “G”):

| sectors | address | size | role |
|---|---|---|---|
| 0–3 | `0x08000000–0x0800FFFF` | 4×16 KB | bootloader |
| 4 | `0x08010000–0x0801FFFF` | 64 KB | bootloader (the `0x402` UPG header lands at its tail `0x0801FBFE`) |
| **5–9** | **`0x08020000–0x080BFFFF`** | **5×128 KB = 640 KB** | **main app — custom firmware links here** |
| 10–11 | `0x080C0000–0x080FFFFF` | 2×128 KB = 256 KB | logs / config |

**RAM layout — byte-derived from the ARM scatterload region table** (`adr@0x45E` → `sl/fp` → 4×{load,
exec, size, fn}): `.data` copy 952 B → `0x20000000`, `.data` decompress 1932 B → `0x200003B8`, `.bss`
zero 147 924 B → `0x20000B44` (**end `0x20024D18`** = stock vector SP), CCM `.bss` zero 65 068 B →
`0x10000000`. Main SRAM 192 KB (`0x20000000–0x2002FFFF`), **MSP stack top `0x20030000`**, CCM 64 KB.
Free scratch gap `0x20024D18..0x20030000` = 45 800 B. The scatterload relocates **data only** ⇒ code
(incl. FatFs) runs in place; only the flash writer is SRAM-copied (§5.13b).

**Linker script (emitted by `analyze83`).** A custom app links at `0x08020000` (sector 5):
`FLASH rx ORIGIN=0x08020000 LENGTH=640K`, `RAM rwx ORIGIN=0x20000000 LENGTH=192K`, `CCM rwx
ORIGIN=0x10000000 LENGTH=64K`; `.isr_vector` first (vector[0]=SP=`_estack`=0x20030000, [1]=Reset_Handler),
`.text/.rodata` in FLASH, `.data` `>RAM AT>FLASH`, `.bss` in RAM, `.ccm_bss` in CCM. The
**Reset_Handler must self-bootstrap** (the boot patches nothing, §5.16): set MSP/PSP from `vector[0]`,
`VTOR=0x08020000`, zero `.bss`+CCM, copy `.data`, call `main` — mirroring the stock startup @`0x08020008`.

**UPG packaging (the transform `make_service_upg.py` implements, §5.13).** Self-described outer XOR key
(`key0=raw[0]`, `key1=raw[0]^raw[1]`); decoded layout `dec[0:2]` key-echo, `dec[2:0x58]` `$$` header,
`dec[0x58:0x400]` discarded prefix (keep stock), `dec[0x400:0x402]` 2 discarded bytes,
`dec[0x402:0x40A]` vector SP+reset, `dec[0x40A:]` app code. Re-seal: length u32LE `@0x3F2` =
`filesize−0x404`; footer CRC u16LE `@0x3FE` = CRC16/MODBUS(`dec[0x3EA:0x3FE]`); trailer `dec[n−4:n]` =
`00 00` + CRC16/MODBUS(`dec[2:n−2]`) (poly `0xA001`, init `0xFFFF`, refin/refout, xorout 0). Re-XOR,
name `MAIN_CCS2CHADEMO_1.UPG`, put on a FAT32 stick root (label not checked).

**Install + entry (boot side, §5.16 ground truth).** The boot XOR-decodes + CRC-verifies, **strips the
`0x402` header and copies `fw[0x402:]` verbatim to `0x08020000`** — no cipher, no patch. Boot-time check
= CRC16/MODBUS residue + config-block additive checksum/magic `0x55AA55AA`; **no whole-image hash**. The
app self-bootstraps from its own vectors; the boot does not write MSP/VTOR (§5.15).

**Stock recovery (bricking-safe).** The bootloader (sectors 0–4) is **never touched by a MAIN update** ⇒
it survives a failed app flash and is the recovery anchor. **`SERVICE.UPG`** = byte-identical stock
round-trip (`make_service_upg.py STOCK -o SERVICE.UPG`) re-flashes the exact stock app. The boot also has
its own **USB update path + XMODEM-1K serial recovery**; **SWD read is non-destructive at RDP0** (never
RDP-unlock — that mass-erases; `acq/` kit = ESP32-S3 CMSIS-DAP + OpenOCD).

**Net for the goal:** the *flash-and-recover* half is fully solved and bench-proven — a custom app linked
per the script above, wrapped by `make_service_upg.py`, is vendor-bootable and reversible. The *safe-charge*
half needs the charge controller (§5.17 state machine + engagement guard + interlocks, §5.18 H108/H109
output law) reimplemented on this layout; the measurement/control details it depends on are now decoded —
the HV raw→volts law + vehicle-request current control in §5.21 (`analyze85`), the timebase in §5.20
(`analyze84`), and the CP/PP IEC thresholds in §5.5b. Layout re-derived from bytes by `analyze83.py`.

### 5.20 Timebase + OS tick — DECODED (C013, `analyze84`)  [H]

`analyze84.py` re-derives the firmware timebase from the timer-init writes and resolves the long-standing
"TIM2 has no LDR-literal base loads" mystery (§8.5).

**Free-running 100 kHz counters.** The timer-base-init function (f+`0x6A544` = `0x0808A142`, located by
its TIM3 `0x40000400` base load) programs three timers as free-running 16-bit timebases:

| timer | base | PSC (+0x28) | ARR (+0x2C) | clock | rate |
|---|---|---|---|---|---|
| TIM1 | `0x40010000` | 1679 | `0xFFFF` | 168 MHz (APB2 ×2) | 100 kHz |
| TIM2 | `0x40000000` | 839 | `0xFFFF` | 84 MHz (APB1 ×2) | 100 kHz |
| TIM3 | `0x40000400` | 839 | `0xFFFF` | 84 MHz (APB1 ×2) | 100 kHz |

All three give **10 µs/tick** (`clk/(PSC+1)`); `ARR=0xFFFF` ⇒ free-running, no periodic interrupt. TIM4 is
the CP PWM input-capture timer (§5.5b), not a timebase.

**TIM2 base is COMPUTED, not loaded.** The init tracks the base register `r1` through
`lsls r1,r1,#0xE`: TIM1 `0x40010000 << 14 = 0x40000000` = TIM2. That is why a whole-image LDR-literal scan
for `0x40000000` finds **zero** TIM2 base loads (the raw pool-word matches at f+`0x911A0`+ are misaligned
sector-size table entries, not code). TIM3 is loaded explicitly; TIM2 is derived from TIM1 by the shift.

**SysTick = free-running timestamp.** `LOAD=0xFFFFFF` (`mvn #0xFF000000`), `CTRL=1` (ENABLE only, no
TICKINT) ⇒ a free-running down-counter used as a fine timestamp, not the OS tick.

**OS tick = 100 Hz (10 ms), software counter.** The timestamp getter `0x0808A236`
(`ldr r0,=0x20000A50; ldr r0,[r0,#4]; bx lr`) returns the **software tick counter `0x20000A54`**, the value
every stm log/timeout reads. It is incremented by the uC/OS-II tick ISR (`OSTimeTick`). The 100 Hz rate is
inferred from the stm timeout constants, all of which land on whole seconds at 10 ms/tick: engagement
guard `≥250` ≈ 2.5 s, state-17 wait `424` ≈ 4.24 s, CurrentDemand adjust `125` ≈ 1.25 s, whole-bus watchdog
`1525` ≈ 15.25 s, CAN watchdogs 1 s/15 s (§5.17). Timer-callback registration `0x0808A26C` uses mutex
`0x20000A60` and a 4-slot table `0x20024254` (stride `0xC`: {fn, arg, active}) for periodic callbacks.

**Net:** the charge controller runs on a 100 Hz OS tick; all §5.17/§5.18/§5.21 timeout/period constants are
in 10 ms units, and the 100 kHz TIMx counters provide 10 µs busy-delay/timestamp resolution. Re-derived
from C013 bytes by `analyze84.py`.

### 5.21 HV measurement law + vehicle-request current control — DECODED (C013, `analyze85`)  [D/E]

`analyze85.py` closes roadmap D (ADC scaling) and E (current/voltage control law): how the DC-link HV
voltage becomes volts (`get_hv`), and how the vehicle's H102 request drives the output-current setpoint.

**D — the `get_hv` raw→volts chain.** The HV DC-link is sampled by **ADC1+ADC2 dual simultaneous**
(PB0/PB1), DMA buffer `0x20022640`, init/calibration f+`0x68986` (§5.17). The chain is:

1. **Vrefint calibration** (f+`0x68986`): the internal-reference raw reading produces two halfword factors
   stored in the cal struct `0x200009C0`: `+2 = 162981000/vref_raw`, `+6 = 180180000/vref_raw`. These
   compensate VDDA drift ratiometrically.
2. **Calibrated-read primitive `0x0808883A`** (a leaf): `ldr r0,=0x200009C0; ldr r1,[r0,#0xc]` (channel
   raw); `ldrh r0,[r0,#2]` (factor); `muls r1,r0,r1; movw r0,#0x3ffc; udiv r0,r1,r0; bx lr` ⇒
   **`reading = raw × Vrefint_factor / 16380`** (`0x3FFC = 4095×4`, the 12-bit full-scale ×4).
3. **Live HV raw global `0x200008B0`** holds the calibrated HV measurement fed to `get_hv`.
4. **`get_hv` `0x08052770` = two-point interpolation** through a **factory-persisted NV cal struct
   `0x20019094`** (getter `0x08052356`, lazy init `0x0805231E`): 0x44 bytes, erased sentinel `0xFE000`,
   validity magic `0x41444A67` @`+0x3C`, checksum over the first 0x10 bytes (fn `0x0805236A`) stored
   @`+0x40`. Fields: `+0x0C` raw_hi, `+0x10` raw_lo, `+0x14` eng_hi, `+0x18` eng_lo. The body
   (`ldrd [r0,#0xc]`, load `0x200008B0`, `smull`, `bl 0x0809E322` = `__aeabi_ldivmod`, signed 64÷64)
   computes **`get_hv = eng_lo + (live_raw − raw_lo)·(eng_hi − eng_lo)/(raw_hi − raw_lo)`**.
5. **`outvol = get_hv()/10` (volts)** → `p[+0x16]` (state-17 handler f+`0x23B88`: `bl get_hv; movs r1,#0xa;
   sdiv r0,r0,r1; strh r0,[r4,#0x16]`). This is the `outvol` the §5.17 engagement guard compares against
   `ress_vol`. *(The earlier "time getter" label for `0x08052770` in §5.18/`analyze82` was wrong — it is
   `get_hv`; corrected.)*

Related analog front-end: the power-stage feedback monitor `0x080524FC` reads the calibrated ADC
(`0x0808883A`), compares against thresholds **8000 / 10500**, debounces **100 ticks**, and drives the
PreChargeRELAY (`0x08088498`, PB10/PB11). The isolation getter `0x0805206C` reads struct `0x20000868`
{`+0` valid, `+1` level (bit1 = warning), `+2` mode}; state-30 requires isolation `==3`, the engagement
guard `==4` (§5.17).

**D-addendum — full measurement front-end + factory-cal source (`analyze88`, custom_fw HV layer).**
The complete acquisition chain is now byte-derived, and it corrects three points in the sketch above:

- **Factory cal lives in an EXTERNAL 2 MB SPI flash, not internal flash.** The NV read core
  `0x08088CFE` (mutex-wrapped by `0x08088F44`) is a standard SPI-flash **READ `0x03`**: it loads
  **SPI4 `0x40013400`**, range-checks `[src, src+len) < 0x200000` (2 MB), asserts **CS = PE11**
  (active-low, `GPIOE_BSRR = 0x08000000`), sends `0x03` + 24-bit address MSB-first, clocks out `len`
  bytes with dummy `0x00` writes (polling TXE), then deasserts CS (`BSRR = 0x800`). **`0xFE000` is the
  flash OFFSET of the cal record** (not an "erased sentinel"). SPI4 init `0x08088C38`: `CR1 = 0x344`
  (CPOL=0/CPHA=0 mode 0, master, BR=/2 → 42 MHz, 8-bit, MSB-first, SSM+SSI, SPE), `CR2 = 0`;
  SCK=PE12 / MISO=PE13 / MOSI=PE14 (AF5). App flashing writes only internal sectors 5–9, so this
  external NV region is **preserved** — a custom app reads the stock factory cal directly (no bench
  calibration required).
- **Checksum is over 16 WORDS (0x40 bytes), not 0x10 bytes.** The checksum fn `0x0805236A` loops
  `r1 = 0x10` times with `ldm r2!,{r3}` (a **word** per step) ⇒ additive sum of `words[0..15]`
  (offsets `0x00..0x3F`) compared to `word[+0x40]`. Validation (lazy-init `0x0805231E`):
  `word[+0x3C] == 0x41444A67`, `word[+0x38] != 0`, checksum match. `get_hv` fields confirmed:
  `raw_hi=+0x0C, raw_lo=+0x10, eng_hi=+0x14, eng_lo=+0x18` (32-bit signed).
- **`get_hv`'s `live_raw` is NOT Vrefint-calibrated.** The Vrefint factors / calibrated-read
  `0x0808883A` feed the **separate** power-stage monitor `0x080524FC` (thresholds 8000/10500). The
  `get_hv` path uses the raw accumulated differential below, directly.

**ADC front-end (init `0x08088584`), all register values byte-derived:**

| block | config |
|---|---|
| ADC1 `0x40012000` | `CR1=0x800` (discontinuous, 1 conv/trigger), `CR2=0x1E000001` (ADON + EXTSEL=14 **TIM8_TRGO** + rising edge), `SMPR1=0x04924924` `SMPR2=0x24924924` (84-cycle sample), `SQR1/2/3=0x00742108/0x10842108/0x10842108` = **8× channel 8 (PB0)** |
| ADC2 `0x40012100` | same CR1/CR2/SMPR, `SQR1/2/3=0x0074A529/0x1294A529/0x1294A529` = **8× channel 9 (PB1)** |
| ADC common `0x40012300` | `CCR=0x2A006`: **MULTI=6** regular-simultaneous ADC1+ADC2, **DMA mode 2** (32-bit CDR), **ADCPRE=/6** (84/6 = 14 MHz ADC clock) |
| DMA2 stream0 ch0 | `CR=0x5518` (circular, 32-bit, MINC, TCIE+HTIE), `NDTR=16`, `PAR=ADC_CDR (0x40012308)`, `M0AR=0x20022640`, enabled last |
| TIM8 `0x40010400` | `PSC=0`, `ARR=0x53F` (1343), `CR2=0x20` (TRGO=update), `CR1=0x95` ⇒ 168 MHz/1344 = **125 kHz** conversion trigger |

**DSP (DMA ISR `0x080886BC` + accumulator `0x08088748`).** On HTIF0 the ISR processes buffer words
0..7, on TCIF0 words 8..15 (8 dual-samples per half; each CDR word = ADC1 low16 | ADC2 high16). Per
half it computes **`diff = sum(ADC1 low16) − sum(ADC2 high16)`** (the **PB0 − PB1 differential**),
accumulates into cal `+0x2C`, and counts cal `+8`. After **3125 (`0xC35`) half-buffer events =
25000 differential samples (~200 ms)** it publishes the accumulated sum as **`live_raw`
(`0x200008B0`)** and resets. The publish is a **tail-branch `b.w 0x08052764`** (`set_live_raw`),
*not* a `bl` — which is why a BL-xref scan of the setter finds no callers. `get_hv` then interpolates
`live_raw` against the factory `raw_lo/raw_hi` (same accumulated-differential scale) → `outvol`.

**custom_fw HV layer (faithful replica, INERT).** `src/spi4.c` (SPI4 init + READ `0x03`),
`src/nv_cal.c` (read + validate the stock cal record), `src/adc.c` (ADC1+ADC2/DMA2/TIM8 verbatim +
the differential-accumulation `DMA2_Stream0_IRQHandler`, IRQ56), `src/hv.c` (`get_hv` +
`outvol=get_hv()/10`). The result is published as SWD-readable globals (`hv_outvol/hv_raw/hv_adc_raw/
hv_cal_ok`) and in H108 byte1-2 (450-clamped) for CAN-bench validation. **No power-stage drive**;
`outvol` accuracy must be bench-verified against a reference before the gated engagement/power layer.
Re-derived from C013 bytes by `analyze88.py`.

**E — vehicle-request → output-current control law.** The adapter parses the vehicle's **H102** request
into the stm context: `p[+0x1d8]` = status byte, `p[+0x1da]` = **TargetBatteryVoltage** (halfword),
`p[+0x1dc]` = **ChargingCurrentRequest** (byte). The control flow:

- **State-17** engages when `ChargingCurrentRequest > 0 A`; its wait counter `p[+0x14]` times out at
  **424 ticks (~4.24 s)**; it logs `outvol`/request every 50 ticks. **State-19** sets the precharge relay.
- **State-30 (CurrentDemand)** regulates the output: it recomputes `outvol = get_hv()/10`, increments a
  phase counter `p[+0x1d2]`, and **every 125 ticks (~1.25 s)** adjusts the current limit (→ state 31) —
  the `"every n minute adjusts current limitation"` behavior. It checks isolation `==3` (`0x0805206C`).
- **`setpara` dispatcher `0x0804E884`**: validates `arg2 ∈ {0..5}` (`cbz r0/r1` → return 0; `cmp r2,#1..#5`)
  then jumps to a jump-table handler `0x0804E9AC`; **`arg2=4` = set the output-current limit** (the
  `setpara_maxevsecurrent` cap path). State-30 calls it with `arg2=4`.
- **Output-current setpoint struct `0x20000780`**: `[+0x44]` request → `[+0x40]` setpoint → output register
  (state-30 copies `[+0x44]→[+0x40]` and writes the setpoint halfword). Context init `0x0804EB2E` zeros
  `0x20000780+0x70/0x74` and `0x20016380`, and inits a 512-byte buffer; `0x0804EAEE` resets the H101/H102
  flags `p[+0x1b6/1c2/1d0]`.
- **Whole-bus watchdog**: `p[+4] > 1525` (15.25 s, `movw #0x5f5` @f+`0x29C58`) → state 450 (`0x1C2`) and
  disable d1 — the CAN-loss safe stop. The H108-build scaling converter `0x0804E786` is a clamp
  (`>=7 → 0xFF`) used as a multiplier in the §5.18 `/1000` output scaling.

**Net for safe charge:** the measurement path (Vrefint-calibrated ADC → NV two-point cal → `outvol` volts)
and the control path (H102 request → state-30 periodic current setpoint via `setpara(4)`, capped by the
EVSE max-current parameter, guarded by isolation + the §5.17 voltage-engagement window + the 15.25 s CAN
watchdog) are now byte-derived. A custom controller reproducing these laws on the §5.19 layout has the
information needed for a safe charge. Re-derived from C013 bytes by `analyze85.py`.

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
- `analyze78.py` — **GPIO-output signal mapper (§5.5a/§5.5c/§8.4)**: names the board's relay/e-lock/
  contactor GPIO outputs + status-feedback inputs, re-derived from `firmware.bin` bytes (no hardcoded
  conclusions). Locates the GPIO primitive cluster by its GPIO-base LDR-literal loads + BSRR writes,
  decodes each push-less primitive's port/pin/direction from the BSRR set-shift / IDR-ODR `ubfx` /
  active-low `bics` (flush at `bx lr`; capstone reg IDs are PC=81/LR=80, not 15/14), xrefs each write
  primitive to BL callers + enclosing-function ADR naming strings, finds the e-lock motor driver
  registered as a function pointer into the E_LOCK struct (`0x20000864`) and decodes its 12-entry u16
  pulse-pattern table (`0x080AB604`). Confirms **PreChargeRELAY = PB10/PB11** (feedback PC8),
  **BatteryPower = PD8**, **BatteryCharge = PC9**, **e-lock motor = PD3/PE4** (shift-register pulse driver
  `0x080517C6`, E_LOCK task `0x080515AB`, `led_process` tick misnomer), **CHAdeMO enables = PE7/PE8**,
  **PE10** = CHAdeMO status, **PB12 = PLC D_LINK**, **KEY_LOCK = PD10** / PD9 = e-lock feedback; PB15
  unreferenced. Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze78.py'`.
- `analyze79.py` — **CAN-bus assignment + RCC clock decoder (§5.8.1/§5.8.2/§8.4/§8.5)**: resolves which CAN
  controller carries CHAdeMO vs GB/T and confirms the MCU clock tree, re-derived from `firmware.bin` bytes
  (no hardcoded conclusions). (1) Constant-tracks the RCC clock-config function's `PLLCFGR`/`CFGR`/
  `FLASH_ACR` writes (invalidating tracked registers on memory loads / RMW so a stale base can't overwrite
  a config value) and decodes the PLL/bus prescalers → SYSCLK 168 / APB1 42 / APB2 84 MHz. (2) Counts
  CAN1/CAN2 base LDR-literal load sites (7 vs 1) and locates the generic CAN-open's `cmp base,CAN1; bne`
  filter-bank skip (tracking the base register from the `tbb` dispatcher's prologue, not stopping at
  case-arm pops). (3) Finds the `CAN1_REC` task by name → entry → the cfg event queue it waits on
  (`0x20000978`, the r0 arg to event-wait `0x080893EA`) and matches it to the CAN1 handle cfg word.
  (4) Disassembles the frame dispatch `0x080524FE` to show the IDE-bit protocol split (11-bit→CHAdeMO,
  29-bit→GB/T J1939). (5) Counts CAN2 stop-thunk BL callers (0). Confirms a **CAN1-only board** carrying
  **both** protocols on CAN1; CAN2 is unwired generic-HAL scaffolding. Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze79.py'`.
- `analyze80.py` — **CHAdeMO charge state-machine mapper (§5.17/§5.2/§5.11)**: re-derives the safe-charge
  state machine from the **C013** firmware (`.qwen/tmp/c013/decoded_c013.bin`, the revision with the proven
  precharge-wait fix). Xrefs every `CHAdeMO stm` log string (full NUL-bounded start incl. the `[%t]#`
  prefix; LDR-literal T1/T2 + ADR T1, one pass), parses the numbered case labels into a state skeleton,
  walks the code region tracking movs/mov.w/movw immediates to extract each `p->state` transition write
  (`strh rX,[r4,#2]`, state halfword @+0x02) with its decoded next-state value, and disassembles the
  state-17 precharge voltage-match guard (outvol @+0x16 ∈ [ress_vol−10, ress_vol+5], counter @+0x0A ≥250,
  isolation==4 → state 17→18). Lists the safety-stop/abort/isolation/welding/unlock interlocks. Run:
  `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze80.py'`.
- `analyze81.py` — **C013 power-stage control mapper (§5.17/§5.5c/§8.5)**: ties the charge state-machine
  actions to the physical GPIO outputs + HV ADC measurement, re-derived from the **C013** bytes. Decodes
  the C013 GPIO primitive cluster (push-less BSRR-write / IDR-ODR-read leaves, shifted to `0x08088400`+),
  names each write primitive via BL-callers → enclosing-function naming strings (PreChargeRELAY=PB10/PB11,
  BatteryPower=PD8, BatteryCharge=PC9, CHAdeMO enables=PE7/PE8, e-lock=PD3/PE4 — hardware-invariant vs
  C009 `analyze78`), and locates the HV ADC front-end by its ADC12_COMMON base loads: disassembles the
  ADC init/calibration function and reports the Vrefint-referenced `udiv` scale factors (162981000/raw,
  180180000/raw → calibration struct `0x200009C0`) + DMA2. The full `get_hv` raw→volts getter is pending.
  Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze81.py'`.
- `analyze82.py` — **CHAdeMO message-layer + output control-law mapper (§5.18/§5.17, roadmap E)**:
  re-derives from **C013** bytes how the adapter (as CHAdeMO charger) builds/transmits the periodic
  H108/H109 status messages. Scans for the CAN-ID store pattern (`mov r1,#ID; str r1,[rX,#0x60]`) to
  locate the senders byte-derived, decodes each 8-byte payload packing (context offset → CAN byte, incl.
  `lsrs #8` high-byte splits + the H109 byte-5 bit-reversal), and tracks the build scaling law (register
  `udiv` /1000, the 450/0x1C2 output clamp, periodic state-gating) + the CAN TX path (fn-ptr `p[+0x270]`
  → `0x08052EE2`, mutex `0x200007E8`, buffer `p[+0x25C]`). The vehicle-request parse + `setpara_maxevsecurrent`
  cap are pending. Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze82.py'`.
- `analyze83.py` — **memory/linker layout + custom-firmware build/flash/recovery recipe (§5.19, roadmap F)**:
  consolidates the bricking-critical layout from `firmware.bin` bytes. Decodes the flash-writer's two
  12-entry sector tables (sizes @`0x9119E`, start-offsets @`0x911CE`) → the exact 1 MB/12-sector flash map
  (boot 0–4, app 5–9 @`0x08020000`, logs 10–11); decodes the ARM scatterload region table (`adr@0x45E` →
  4×{load,exec,size,fn}) → `.data`/`.bss`/CCM regions, `.bss` end `0x20024D18`, stack top `0x20030000`,
  free scratch gap; emits a GNU ld linker script for a custom app at `0x08020000` (self-bootstrapping
  Reset_Handler); and prints the UPG packaging + verbatim-install + stock-recovery recipe (the transform
  `make_service_upg.py` implements). Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze83.py'`.
- `analyze84.py` — **timebase + OS-tick decoder (§5.20/§8.5, roadmap H)**: re-derives the firmware timebase
  from the C013 timer-init writes. Locates the timer-base-init function by its TIM3 `0x40000400` base load,
  tracks the base register through `lsls r1,r1,#14` (TIM1 `0x40010000`<<14 = TIM2 `0x40000000`) and the
  PSC/ARR/CR1 constant writes → TIM1 PSC=1679 (168 MHz/1680), TIM2/TIM3 PSC=839 (84 MHz/840), all 100 kHz
  free-running (`ARR=0xFFFF`, 10 µs/tick). **Resolves the "TIM2 has zero LDR-literal base loads" mystery:
  its base is COMPUTED, not loaded.** Decodes SysTick (LOAD=0xFFFFFF, CTRL=1, free-running, no TICKINT),
  the software-tick getter `0x0808A236` (counter `0x20000A54`), and the 4-slot timer-callback table
  `0x20024254`; infers OS tick = 100 Hz from the stm timeout constants.
  Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze84.py'`.
- `analyze85.py` — **HV measurement law + vehicle-request current-control decoder (§5.21, roadmap D/E)**:
  re-derives from C013 bytes (1) the ADC calibrated-read primitive `0x0808883A` (`raw × Vrefint_factor /
  16380`, cal struct `0x200009C0`); (2) `get_hv` `0x08052770` = two-point interpolation through the
  factory-persisted NV cal struct `0x20019094` (magic `0x41444A67`, checksum-validated), live raw global
  `0x200008B0`, signed 64-bit `smull`+`__aeabi_ldivmod`; confirms `outvol = get_hv()/10` via the state-17
  store; (3) the vehicle-request control law — whole-bus watchdog `p[+4]>1525`→state 450, CurrentDemand
  periodic adjust `p[+0x1d2]`≥125, the `setpara` dispatcher `0x0804E884` (arg2 selector 0..5, =4 current
  limit), output-current setpoint struct `0x20000780` (`[+0x44]→[+0x40]`), and the parsed H102 fields
  (`p[+0x1d8/1da/1dc]`). Corrects the §5.18 "time getter" mislabel (`0x08052770` = `get_hv`).
  Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze85.py'`.
- `analyze86.py` — **power-stage GPIO active-level + safe-state decoder (§5.5c/§5.17, custom_fw)**:
  complements analyze78/81 (which named the pins) by decoding each C013 drive primitive's BSRR
  set/reset logic to fix the pin ACTIVE level, then deriving the SAFE (de-asserted) boot level the
  custom firmware drives so every contactor stays open. active-HIGH (cmd→SET): CHAdeMO d1/d2 PE7/PE8,
  BatteryPower PD8, PreChargeRELAY PB10/PB11 ⇒ SAFE=LOW; active-LOW (`bics` inverted cmd→RESET):
  BatteryCharge PC9, e-lock PD3/PE4 ⇒ SAFE=HIGH. Notes the PreCharge reset-mask address-bit trick
  (`lsls r2, r1, #0x10/0x11`, GPIOB base bit10 → `(1<<10/11)<<16`). Emits the `gpio_safe_init` table.
  Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze86.py'`.
- `analyze87.py` — **CHAdeMO RX message-parse decoder (§5.8.4/§5.18/§5.21, custom_fw CAN1 layer)**:
  decodes the C013 H100/H101/H102 receive parse from bytes — the CAN-ID dispatch (`cmp #0x102` →
  handler `0x0803BB72`), the little-endian halfword helper `0x08050976` (`b0|b1<<8`), and each
  message's CAN-data-byte → stm-context stores. The RX frame buffer `p[+0x260]` has a 4-byte ID
  header so CAN byte N = buf[4+N]. H102: byte0=status `p+0x1d8`, byte1-2=TargetBatteryVoltage
  `p+0x1da` (LE), byte3=ChargingCurrentRequest `p+0x1dc`, byte4/5=fault `p+0x1dd/1de`. Reconciles the
  §5.10 tentative "byte0=current request" reading (parse places it at byte3). Backs `custom_fw/src/chademo.c`.
  Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze87.py'`.
- `analyze88.py` — **HV measurement-chain decoder (§5.21 D-addendum, custom_fw HV layer)**: decodes the
  C013 factory-calibrated HV front-end from bytes — SPI4 init `0x08088C38` (`CR1=0x344`) + NV read core
  `0x08088CFE` (external 2 MB SPI-flash READ `0x03`, CS=PE11, cal record @`0xFE000`); NV cal lazy-init
  `0x0805231E` validation (magic `0x41444A67`@`+0x3C`, `[+0x38]!=0`, **16-word** additive checksum vs
  `+0x40`) + `get_hv` `0x08052770` field offsets/interpolation; ADC init `0x08088584` (ADC1 8×ch8 PB0 +
  ADC2 8×ch9 PB1 regular-simultaneous `CCR=0x2A006`, DMA2 stream0 `CR=0x5518` NDTR=16, TIM8 125 kHz
  trigger); DMA ISR `0x080886BC` + accumulator `0x08088748` (PB0−PB1 differential sum, 3125 events =
  25000 samples → `live_raw`, published via tail-branch `b.w set_live_raw`). Corrects the §5.21 sketch:
  cal is in **external SPI flash** (not internal), checksum is 16 **words** (not 0x10 bytes), and
  `get_hv`'s `live_raw` is **not** Vrefint-calibrated (that feeds the separate power-stage monitor).
  Backs `custom_fw/src/{spi4,nv_cal,adc,hv}.c`.
  Run: `nix-shell -p python3 python3Packages.capstone --run 'python3 analyze88.py'`.
- `make_service_upg.py` — **service-UPG builder (§5.13e/f/i)**: implements the cracked format/integrity —
  derive key, XOR-decode, patch app / append cave, re-seal length + both MODBUS CRCs, re-XOR; preserves
  prefix/entry/first4 verbatim. `STOCK -o OUT` (byte-identical round-trip), `--patch OFF:HEX`,
  `--dump-hook` (bootloader-dump cave, bench-confirmed), `--dump-app5` (running-app sector-5 dump cave,
  §5.13i), `--verify-only`. `build_dump_hook` is parameterized (dump base/len/path/magic); defaults
  reproduce the proven boot cave byte-for-byte. Emits `SERVICE.UPG` (safe, stock-equivalent),
  `SERVICE_DUMP.UPG` (bench-confirmed — produced `BOOT.BIN`), `SERVICE_DUMP_APP5.UPG` (§5.13i).
- `make_custom_upg.py` — **whole-app custom-UPG wrapper (§5.19/§5.16)**: extends the cracked format to a
  full app replacement (which `make_service_upg.py` cannot do — it preserves the stock entry shell
  `[0x400:0x45E]`). Keeps stock `[0:0x3EA]` key/header/prefix + `[0x400:0x402]` entry bytes verbatim, sets
  `[0x402:] =` the custom app binary (vectors+code linked at `0x08020000`), re-seals length `@0x3F2` +
  both CRC16/MODBUS checksums, re-XORs. The boot installs `fw[0x402:]` verbatim and branches to the app
  reset vector, so the app runs as linked. Verified: boot CRC-append residue = 0, app verbatim, and a
  byte-identical round-trip when fed the stock app region. `STOCK.UPG app.bin -o CUSTOM.UPG`.
- `custom_fw/` — **flashable custom-app safe-bootstrap + CAN1 message layer + HV measurement + inert
  charge state machine (§5.19, build/flash/recovery pipeline proof + charge-controller base)**: `linker.ld` (FLASH `0x08020000` 640K / RAM `0x20000000` 192K /
  CCM 64K, `_estack=0x20030000`), `startup.s` (vector table + self-bootstrapping Reset_Handler: MSP from
  `vector[0]`, `VTOR=0x08020000`, copy `.data`, zero `.bss`+CCM, call `main`; weak core/CAN1 IRQ19–22 handler
  aliases — the boot writes no MSP/VTOR, §5.15/§5.16), `src/rcc.c` (restore SYSCLK 168 MHz HSE→PLL, APB1 42/
  APB2 84, FLASH 5WS, PWR VOS scale1 — §5.8.1), `src/gpio.c` (`gpio_safe_init`: BSRR pre-load of SAFE/
  de-asserted levels then MODER→output, glitch-free; contactors open, no HV — §5.5c, analyze86), `src/tick.c`
  (100 Hz SysTick OS tick + 100 kHz TIM2 timebase — §5.20), `src/can.c` (bxCAN CAN1 500k BTR `0x00270006`,
  MCR `0x4D`, PD0/PD1 AF9, bank-0 mask filter accept `0x100..0x103`, FIFO0-pending RX ISR→ring, polled TX,
  bus-off recovery — §5.8.2), `src/chademo.c` (H100/H101/H102 RX parse per analyze87 + periodic H108/H109
  standby TX with measured outvol in H108 byte1-2, per-message + whole-bus watchdog timestamps — §5.18),
  **HV measurement layer (§5.21 D-addendum, analyze88)**: `src/spi4.c` (SPI4 `CR1=0x344` + external-flash
  READ `0x03`, CS=PE11), `src/nv_cal.c` (read + validate the stock factory cal @`0xFE000`, magic + 16-word
  checksum), `src/adc.c` (ADC1 8×ch8 PB0 + ADC2 8×ch9 PB1 simultaneous `CCR=0x2A006`, DMA2 stream0
  `CR=0x5518`, TIM8 125 kHz, differential-accumulation `DMA2_Stream0_IRQHandler` IRQ56 → `live_raw`),
  `src/hv.c` (`get_hv` interpolation + `outvol=get_hv()/10`, libgcc `__aeabi_ldivmod`);
  **inert charge state machine (§5.17, analyze80/analyze85)**: `src/charge_stm.c` (shadow controller —
  safe-charge sequence 13→…→30 + stop/shutdown skeleton, **byte-exact state-17 engagement guard**
  `charge_stm_engage_ok` [flag==1 && isolation==4 && outvol∈[ress_vol−10,ress_vol+5] unsigned && dwell≥250],
  interlocks [whole-bus 1525→450, per-msg 100, H102 fault→300, emergency→40, bms/hw→600, CurrentDemand
  isolation==3], records but does NOT execute `STM_ACT_*` power actions; EVSE-side handshake inputs
  safe-stubbed until the CCS2 PLC/DIN layer; host-unit-tested `test_charge_stm.c` 47 checks); `main.c`
  (rcc→gpio_safe→**hv**→can→chademo→**charge_stm**→tick→`cpsie i`, then 100 Hz loop: IWDG feed + `heartbeat`
  + publish `hv_outvol/hv_raw/hv_adc_raw/hv_cal_ok` + RX parse + **charge_stm_step** (publish `stm_state/
  stm_interlock/stm_engage/stm_action`) + periodic TX + can_service; **no ASSERTED power-stage drive**),
  `build.sh`/`verify_pad.py`/`README.md`. Built + verified (5444 B code, vectors
  `MSP=0x20030000`/`reset=0x080201AD`, SysTick + CAN1_RX0 + DMA2_Stream0 strong overrides at IRQ15/IRQ20/
  IRQ56 confirmed, adc_init/spi4_init/hv_get_raw register writes + interpolation + engagement-guard compares
  disasm-checked, charge_stm_step has no peripheral/GPIO stores, CRC residue 0). `outvol` accuracy must be
  bench-verified vs a reference before the gated engagement/power layer.
  Power-stage drive stays GATED behind a compile-time safety flag until bench-validated; grow via §5.21
  H102 current control. Build outputs git-ignored; `CUSTOM.UPG` is a bench-flash candidate (untracked).
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
4. **Pin map — RESOLVED (§5.5a, `analyze74`); ADC-channel→CP/PP map RESOLVED + NAMED (§5.5b, `analyze77`); GPIO-output signals NAMED (§5.5c, `analyze78`).**
   The board GPIO init @`0x08087010` (f+`0x67412`) writes
   standard STM32F4 GPIO register values from a literal pool at f+`0x67756` (the earlier "custom packed
   format" guess was wrong — it is just MODER/OTYPER/OSPEEDR/PUPDR/ODR/AFR constants), then locks all pins
   via the helper @`0x08087340`. Decoded: **SPI1/QCA7005 = PA5/6/7 (AF5)**, **SPI4/flash = PE12/13/14 (AF5)**,
   **USART1 = PA9/10 (AF7)**, **USB FS = PA11/12 (AF10)**, **CAN1 = PD0/PD1 (AF9)**, TIM4_CH1 = PD12 (AF2,
   **CP PWM input-capture**); GPIOA–E used (no F–K). **ADC signals named** by the firmware "Hardware
   Information" dumper (`0x0804E92C`): **CP DC level = PA0/ADC3_IN0 (`AD_CPD`)**, **PP = PA2/ADC3_IN2
   (`AD_PP`)**, PC2 = `AD_BAT` (battery, 2:1 divider), PA1 = `+24V` rail, **PB0−PB1 (ADC1+ADC2 dual
   simultaneous) = `HV` DC-link voltage**; CP PWM duty/freq = TIM4_CH1/PD12 capture (not ADC), decoded to
   current by the IEC 61851-1 law (§5.5b). **GPIO-output signals named (§5.5c, `analyze78`):**
   PreChargeRELAY = PB10/PB11 (feedback PC8), BatteryPower = PD8, BatteryCharge = PC9, e-lock motor =
   PD3/PE4 (shift-register pulse drive, profile table `0x080AB604`, E_LOCK task `0x080515AB`), CHAdeMO
   enables = PE7/PE8; feedback inputs KEY_LOCK = PD10, PD9 (e-lock), PE10 (CHAdeMO), PB12 = PLC D_LINK,
   PC8 (PreChargeRELAY); PB15 unreferenced. **CAN2 GPIO — RESOLVED (`analyze79`, §5.8.2): CAN1-only
   board** (CAN2 has no AF9 pins, no service task, and an unreferenced stop thunk — it is unwired).
   **Remaining:** LED drive pins (the `led_process` label is the e-lock tick, not a separate LED block).
5. **CAN IDs & timing** — **LARGELY RESOLVED (§5.8).** Extracted: GB/T J1939 RX/TX/TP ID tables (SA `0x56`/`0xF4`), CHAdeMO H100–H112 + CBMS set, baud table {125,250,500} k @ APB1=42 MHz (SYSCLK 168 MHz **[C] — confirmed from RCC PLLCFGR/CFGR/FLASH_ACR, `analyze79`**), CAN init/filter config + driver mailbox-FIFO layer (§5.8.2), and protocol timeouts (1/4/5/6/8 s). **CAN1/CAN2→CHAdeMO/GB/T assignment RESOLVED (`analyze79`, §5.8.2): CAN1-only board** — CAN1 (PD0/PD1) carries both protocols via the single `CAN1_REC` task + IDE-split frame dispatch `0x080524FE`; CAN2 unwired. **RTOS tick = 100 Hz / 10 ms RESOLVED** (§5.1/§5.8.5). **TIM2 prescaler + tick constants RESOLVED (`analyze84`, §5.20):** TIM1 PSC=1679 (168 MHz/1680), TIM2/TIM3 PSC=839 (84 MHz/840) → all 100 kHz free-running (10 µs/tick, `ARR=0xFFFF`); TIM2 base is COMPUTED (TIM1 `0x40010000`<<14), not LDR-literal — resolving the zero-load mystery; the second-valued timeouts are 10 ms-unit stm constants (engagement 250, state-17 wait 424, CurrentDemand adjust 125, whole-bus watchdog 1525). **Remaining:** confirm the runtime-built GB/T IDs (CHM/CTS/CRO/CST/CEM/BRM/BCP/BCS).
6. **QCA7005 firmware** — **RESOLVED: not in this update.** Modem boots from external SPI flash; the MCU is only a SLAC/PLC host (§5.3). For open firmware, use the redistributable Qualcomm blob (open-plc-utils / `qca_spi` ecosystem).
7. **RTOS identity — RESOLVED (§5.1, `analyze73`): uC/OS-II (Micrium), customized.** Identified by the
   internal-symbol debug string `OSRdyTbl` (uC/OS-II ready table). Tick = **100 Hz / 10 ms** (stat dump
   `÷100`); customized TCB accessors + `OSTaskCreateExt`-style wrapper @`0x08088D76`; named tasks
   `tcpip_process` (4 KB stack, prio 10) / `led_process` / `PDS_PROCESS` / `iso1_function_res_process`.
8. **EVCC identity details (§5.9)** — EVCCID = the adapter's **6-byte PLC MAC** (confirmed: SLAC EVHost-MAC, `MAC:` prints, and `SessionSetupReq` all use the same global-struct bytes via thunk `0x080890AE`, which indexes a 48-byte-entry array @SRAM `0x2002390C`, pointer at `+0x2C`). **(a) MAC-read MMTYPE RESOLVED** (`analyze75`): chain SLAC banner → `0x0802156C` → `0x08088C10` (mutex + PC5 reset) → `0x08088B94` (QCA7005 SPI signature `0xAA55`@reg`0x1A00`) → `0x08088A0E` (SPI reg init `0x1200=0xC5B`/`0xC00=0x447`/`0xD00=0x41`); then the MAC-read MME = **vendor-specific MMTYPE `0xA000` (REQ) / `0xA001` (CNF)**, MMV `0`, EtherType `0x88E1`, payload param `0xB000` + op `'R'`(`0x52`, Read). Builder `0x08088B48` (12-byte header template `0x080AEC84`, dest = QCA7005 **default** MAC `00:B0:52:00:00:01`; EtherType via `movw #0xE188`+`strh`), validator `0x08088ADA` (CNF `0xA001`, done-marker `0x55`), poll `0x08088B1E` / retry `0x08088C74`; 6-byte MAC → SRAM `0x200227E6` (accessor `0x08088CAC`). SLAC `CM_*` MMTYPEs also decoded: `0x6064/65` `CM_SLAC_PARM`, `0x606A` `CM_START_ATTEN_CHAR`, `0x6008/09` `CM_SET_KEY` (decoder `0x080214D6`). **(b) SDP security trigger RESOLVED + NAMED (`analyze76`):** security = (config byte @SRAM `0x20018A0C` == 0) ? TLS : no-TLS, via accessor `0x08051074` (config struct `0x200189EC`). The byte is the **"Root certs" count** — named by the firmware diagnostic dumper `0x0804EB5C` ("Show Certification Status", f+`0x2F2CA`): config[+`0x20`] = Root certs (msg-code `0x8101`, ≤5), [+`0x21`] = Pri_root cert (`0x8102`), [+`0x22`] = Oem cert (`0x8105`), [+`0x23`] = Contract certs (`0x8109`, 32 B). Flash parser `0x08050E14` copies msg-`0x8101` entries from the PnC cert config block @`0x001F8010` (magic `0xCEA155E1`) into a 5-slot array; config init `0x08050B94` counts them. **Trigger = the ISO 15118 PnC root-certificate configuration** (TLS iff Root-cert count == 0), a service-config property — not DIN-vs-ISO and not per-session. The msg-code set is `0x8101`–`0x8109` (the earlier `0x810D` was a conflation of two functions; no such code).
9. **Device provenance (§5.10)** — vendor **disavows the unit as a clone**; firmware nameplate = **`KM-CCS2CHAdeMO-1`** / `CCS2GBT` with CATL/CAMA BMS code. Identify the **"KM" OEM**: web search was unavailable (2026-11-18, retry); decode the ID-block fields `F$K$N$T$2005$TY/VR$…` (f+0x090df0); check enclosure/label markings and the `SER:202406180463` date-code convention against other units. The USB log **proves the unit runs C009 = `firmware.bin`** (§5.10), so all RE findings apply to this hardware regardless of brand. MAC OUIs are IEEE-RA reference values — not a maker fingerprint.