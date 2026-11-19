# custom_fw — safe-bootstrap + CAN1 message layer (Orientrise KM-CCS2CHAdeMO-1)

A **minimal, flashable, stock-reversible** custom application for the adapter
(STM32F427/F429, Cortex-M4), being built up in incremental, independently-testable layers
toward a safe CHAdeMO charge controller. It proves the full **build → wrap → flash → recover**
pipeline end-to-end on the byte-derived memory layout (REPORT §5.19) and boot entry contract
(§5.15/§5.16). **Current stage: SAFE BOOTSTRAP + CAN1 MESSAGE LAYER** — clocks + timebase +
GPIO safe-state + CAN1 (500k) CHAdeMO RX/TX. It is **not yet a charge controller** and performs
**no asserted power-stage drive** (CAN reporting only).

## Safety — read first

This foundation is **safe-by-construction** (contactors open, no HV):

- **Clocks**: `rcc_init` restores SYSCLK 168 MHz (HSE→PLL, APB1 42 / APB2 84 MHz, FLASH 5WS,
  PWR VOS scale1 — §5.8.1) because the boot deinitialises clocks before jumping to the app.
- **GPIO safe-state**: `gpio_safe_init` drives every power-stage pin to its **SAFE / de-asserted**
  level (§5.5c, `analyze86`) — PE7/PE8 (CHAdeMO d1/d2), PD8 (inner contactor), PB10/PB11
  (precharge) **LOW**; PC9 (charge), PD3/PE4 (e-lock) **HIGH**. It pre-loads these via BSRR while
  the pins are still reset-state inputs, *then* switches MODER to output, so an asserted
  (contactor-closing) level is **never driven, even for a cycle** ⇒ **contactors open, no HV**.
- **No asserted drive**: the functions that *close* contactors / precharge / charge are **not
  implemented yet** and will stay **GATED behind a compile-time safety flag** until bench-validated.
- **Timebase**: `tick_init` starts the 100 Hz SysTick OS tick + 100 kHz TIM2 counter (§5.20).
- **CAN1 message layer**: `can_init` brings up bxCAN CAN1 at 500 kbit/s (PD0/PD1 AF9, BTR
  `0x00270006`, §5.8.2); `chademo` parses RX H100/H101/H102 and sends periodic H108/H109 with a
  **standby status + zero output** (§5.18). This is **communication only** — it drives no power
  pin. The CHAdeMO enables d1/d2 (PE7/PE8) stay LOW (safe), so the power stage remains disabled.
- **IWDG**: the loop feeds the watchdog key (`0x40003000`) — harmless whether or not the IWDG is
  enabled (keeps the app alive if the boot left it running; no-op otherwise).
- A RAM `heartbeat` counter increments each 10 ms tick so you can confirm "the custom app is
  running" over SWD.

Do **not** enable asserted power-stage drive until the charge controller is implemented and
bench-validated against the decoded laws (REPORT §5.17 state machine + engagement guard +
interlocks, §5.18 H108/H109 output, §5.20 100 Hz timebase, §5.21 `get_hv` measurement + H102
current control, §5.5c GPIO map + active levels).

## Files

| file | purpose |
|---|---|
| `linker.ld` | GNU ld script: FLASH `0x08020000` 640K (app sectors 5–9), RAM `0x20000000` 192K, CCM `0x10000000` 64K, `_estack=0x20030000` (§5.19) |
| `startup.s` | vector table + self-bootstrapping `Reset_Handler`: MSP from `vector[0]`, `VTOR=0x08020000`, copy `.data`, zero `.bss`+CCM, call `main`; weak core + CAN1 (IRQ19–22) handler aliases (the boot writes no MSP/VTOR, §5.15/§5.16) |
| `src/rcc.c/.h` | `rcc_init`: restore SYSCLK 168 MHz (HSE→PLL, APB1 42 / APB2 84 MHz, FLASH 5WS, PWR VOS scale1 — §5.8.1) |
| `src/gpio.c/.h` | `gpio_safe_init`: drive all power pins to SAFE/de-asserted levels, glitch-free (BSRR pre-load then MODER→output — §5.5c, `analyze86`); pin map + active levels |
| `src/tick.c/.h` | `tick_init`: 100 Hz SysTick OS tick (`SysTick_Handler`) + 100 kHz TIM2 counter; `tick_get`/`tick_micros`/`tick_delay_ms` (§5.20) |
| `src/can.c/.h` | bxCAN CAN1 transport: 500k (BTR `0x00270006`), MCR `0x4D`, PD0/PD1 AF9, bank-0 mask filter accept `0x100..0x103`, FIFO0-pending RX ISR (`CAN1_RX0_IRQHandler`)→ring, polled TX, bus-off recovery (§5.8.2) |
| `src/chademo.c/.h` | CHAdeMO message layer: RX H100/H101/H102 parse (byte→field per `analyze87`), periodic H108/H109 standby TX, per-message + whole-bus watchdog timestamps (§5.18) |
| `main.c` | rcc→gpio_safe→can→chademo→tick→`cpsie i`, then 100 Hz loop (feed IWDG + `heartbeat` + RX parse + periodic TX + can_service); no asserted power drive |
| `build.sh` | builds via `nix-shell -p gcc-arm-embedded python3` → `app.elf`/`app.bin`, verifies vectors, pads to sector 5 |
| `verify_pad.py` | checks `vector[0]==0x20030000`, `vector[1]` is an in-app Thumb address; pads `app.bin` → `app_padded.bin` (128 KB, `0xFF` tail) |

Build outputs (`app.elf`, `app.map`, `app.bin`, `app_padded.bin`) are git-ignored.

## Build

```sh
bash build.sh
```

Produces `app.bin` (vectors + code, linked at `0x08020000`) and `app_padded.bin` (128 KB =
sector 5, matching the ground-truth `app5.bin` dump). Expected vectors:
`MSP=0x20030000`, `reset=0x080201AD` (handler `0x080201AC`, Thumb bit set). The SysTick vector
(offset `0x3C`) must point to `tick.c`'s strong `SysTick_Handler`, and the CAN1_RX0 vector
(IRQ20, offset `0x90`) to `can.c`'s strong `CAN1_RX0_IRQHandler` (both override the weak aliases).

## Wrap into a bootable UPG

From the repo root (`re/`), using a stock UPG as the key/prefix source (`SERVICE.UPG` is the
byte-identical stock round-trip from `make_service_upg.py`):

```sh
nix-shell -p python3 --run \
  "python3 make_custom_upg.py SERVICE.UPG custom_fw/app_padded.bin -o CUSTOM.UPG"
```

`make_custom_upg.py` keeps the stock `[0:0x3EA]` key/header/prefix + `[0x400:0x402]` entry
bytes verbatim, sets `[0x402:] = app_padded.bin`, re-seals the length field + both
CRC16/MODBUS checksums, and re-XORs. The boot strips the `0x402` header and installs
`fw[0x402:]` **verbatim** at `0x08020000`, then branches to the app reset vector — so the
custom app runs exactly as linked. Verified: CRC residue = 0, app verbatim, and a
byte-identical round-trip when fed the stock app region.

## Flash (bench — your decision)

1. Copy `CUSTOM.UPG` to a **FAT32 USB stick root**, named **`MAIN_CCS2CHADEMO_1.UPG`**
   (the volume label is not checked; the filename is what the boot looks for — confirm
   against your unit's stock update name).
2. Insert into the adapter and trigger the USB update path (as for a stock update). The boot
   XOR-decodes + CRC-verifies in the SPI pool, then installs verbatim to sector 5 and jumps.
3. The app runs the 100 Hz loop feeding the IWDG. Confirm it runs over SWD: halt and read
   `&heartbeat` (incrementing at 100 Hz) or check `PC` is in the `main` loop. On a CAN bench
   (500k, e.g. an ESP32-S3/Arduino-Mega CAN node or analyzer on PD0/PD1) you should see periodic
   **H108 (0x108) / H109 (0x109)** frames every 100 ms with standby status + zero output, and the
   app parses injected H100/H101/H102. **No contactor should click and no HV should appear** — if
   anything energises, stop immediately.

## Recovery (bricking-safe)

The bootloader (sectors 0–4) is **never touched by a MAIN update**, so it survives a failed
app flash and is the recovery anchor. To return to stock:

```sh
nix-shell -p python3 --run "python3 make_service_upg.py SERVICE.UPG -o SERVICE.UPG"  # stock round-trip
```

Flash `SERVICE.UPG` (byte-identical stock app) the same way. The boot also has a USB update
path + XMODEM-1K serial recovery; SWD read is non-destructive at RDP0 (**never RDP-unlock** —
that mass-erases). See REPORT §5.19.

## Growing this into a safe charge controller

Built up in incremental, independently-testable layers; power-stage drive stays GATED last.

**Done (safe bootstrap + CAN1 message layer):**
- Clocks — `rcc_init` restores SYSCLK 168 MHz (§5.8.1).
- §5.20 — 100 Hz SysTick OS tick + 100 kHz TIM2 timebase (`src/tick.c`).
- §5.5c — GPIO **safe-state** init (`src/gpio.c`, active levels via `analyze86`): all power pins
  de-asserted, contactors open. (Asserted drive is a later, gated layer.)
- §5.8.2/§5.18 — CAN1 transport (`src/can.c`, 500k) + CHAdeMO message layer (`src/chademo.c`):
  RX H100/H101/H102 parse (byte→field via `analyze87`), periodic H108/H109 **standby** TX (zero
  output until measurement exists), per-message + whole-bus watchdog timestamps.

**Remaining layers:**
- §5.21 — `get_hv` measurement (Vrefint-calibrated ADC → NV two-point cal → `outvol=get_hv()/10`).
  Note: the custom app lacks the factory NV cal data — needs bench calibration or reading stock cal.
- §5.17 — CHAdeMO charge state machine + state-17 voltage-engagement guard
  (`outvol ∈ [ress_vol−10, ress_vol+5]`) + safety interlocks + CAN watchdogs.
- §5.21 — H102 vehicle-request → output-current control law (`setpara(4)`, struct `0x20000780`).
- §5.5c — **asserted** power-stage drive (PB10/PB11 precharge, PD8 inner contactor, PC9 charge,
  PE7/PE8 d1/d2, PD3/PE4 e-lock) — **LAST**, behind a compile-time safety flag, drive **only** once
  the controller is bench-validated.