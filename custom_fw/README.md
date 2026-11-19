# custom_fw — safe-bootstrap + CAN1 message layer + HV measurement + inert charge stm + inert current control (Orientrise KM-CCS2CHAdeMO-1)

A **minimal, flashable, stock-reversible** custom application for the adapter
(STM32F427/F429, Cortex-M4), being built up in incremental, independently-testable layers
toward a safe CHAdeMO charge controller. It proves the full **build → wrap → flash → recover**
pipeline end-to-end on the byte-derived memory layout (REPORT §5.19) and boot entry contract
(§5.15/§5.16). **Current stage: SAFE BOOTSTRAP + CAN1 MESSAGE LAYER + HV MEASUREMENT + INERT CHARGE
STM + INERT CURRENT CONTROL** — clocks + timebase + GPIO safe-state + CAN1 (500k) CHAdeMO RX/TX + the
factory-calibrated HV measurement front-end (`get_hv` → `outvol`) + the inert charge state machine
(safe-charge sequence + byte-exact state-17 engagement guard + interlocks + CAN watchdogs) + the inert
H102 output-current control law (state-30 `min(request, EVSE avail)` setpoint capped by EVSE max). It
performs **no asserted power-stage drive** — the state machine and current control are *shadow*
controllers that record but do not execute power actions (measurement + CAN reporting + state/setpoint
tracking only).

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
  **standby status** (§5.18). H108 byte1-2 carries the measured `outvol` (450-clamped) for bench
  readout; H109 stays zero. This is **communication only** — it drives no power pin. The CHAdeMO
  enables d1/d2 (PE7/PE8) stay LOW (safe), so the power stage remains disabled.
- **HV measurement**: `hv_init` brings up the factory-calibrated HV front-end (§5.21, `analyze88`) —
  SPI4 reads the **stock factory cal from external flash** (untouched by app flashing), ADC1+ADC2
  simultaneous (PB0/PB1) + TIM8-triggered DMA2 accumulate the differential `live_raw`, and `get_hv`
  interpolates it to `outvol=get_hv()/10`. This is **measurement only** — it samples analog inputs
  and drives no power pin. If no valid cal is found, `outvol` reports 0 (`hv_cal_ok=0`). **Bench-verify
  `outvol` against a known reference before the gated engagement/power layer relies on it.**
- **Inert charge state machine**: `charge_stm_step` runs the C013 safe-charge sequence + the **byte-exact
  state-17 engagement guard** + interlocks + CAN watchdogs (§5.17, `analyze80`) as a **shadow controller** —
  it computes the state and *records* the power action each state would drive (`STM_ACT_*`) but **executes
  no GPIO**. The engagement guard only passes when `flag==1 && isolation==4 && outvol ∈ [ress_vol−10,
  ress_vol+5] && dwell≥250`; the EVSE-side handshake inputs (isolation/precharge_flag/plug_in/…) are
  **safe-stubbed to 0** until the CCS2 PLC/DIN subsystem is built, so the machine holds in the early states
  and **cannot engage**. Interlocks (whole-bus 1525-tick / per-message 100-tick CAN watchdogs, H102 fault,
  emergency, bms/hw fault, CurrentDemand isolation==3) force a safe stop state. Host-unit-tested
  (`test_charge_stm.c`, 47 checks). State/interlock/engage/action are SWD-readable (`stm_*`).
- **Inert H102 current control**: `current_ctrl_step` runs the C013 state-30 CurrentDemand output-current
  law (§5.21 E, `analyze89`) as a **shadow setpoint** — `setpoint = min(H102.ChargingCurrentRequest, EVSE
  available)` capped by the EVSE max-current, `target_v = min(H102.TargetBatteryVoltage, limit)`, with the
  byte-exact `/1000` scaling + converter (`(code<7)?code:0xFF`). It **drives no power stage** (no GPIO/DAC/
  PWM). The EVSE-side measurements (max/available current + range-code factors, voltage limit) come from the
  CCS2 PLC/DIN subsystem not built yet → **safe-stubbed to 0**, so `avail==0` and the `min(request,0)==0`
  zero-skip **holds the setpoint at 0** — no current is ever commanded. It only runs in state-30
  (CurrentDemand). Host-unit-tested (`test_current_ctrl.c`, 42 checks). Setpoint/cap/target are SWD-readable
  (`cc_*`).
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
| `startup.s` | vector table + self-bootstrapping `Reset_Handler`: MSP from `vector[0]`, `VTOR=0x08020000`, copy `.data`, zero `.bss`+CCM, call `main`; weak core + CAN1 (IRQ19–22) + DMA2_Stream0 (IRQ56) handler aliases (the boot writes no MSP/VTOR, §5.15/§5.16) |
| `src/rcc.c/.h` | `rcc_init`: restore SYSCLK 168 MHz (HSE→PLL, APB1 42 / APB2 84 MHz, FLASH 5WS, PWR VOS scale1 — §5.8.1) |
| `src/gpio.c/.h` | `gpio_safe_init`: drive all power pins to SAFE/de-asserted levels, glitch-free (BSRR pre-load then MODER→output — §5.5c, `analyze86`); pin map + active levels |
| `src/tick.c/.h` | `tick_init`: 100 Hz SysTick OS tick (`SysTick_Handler`) + 100 kHz TIM2 counter; `tick_get`/`tick_micros`/`tick_delay_ms` (§5.20) |
| `src/can.c/.h` | bxCAN CAN1 transport: 500k (BTR `0x00270006`), MCR `0x4D`, PD0/PD1 AF9, bank-0 mask filter accept `0x100..0x103`, FIFO0-pending RX ISR (`CAN1_RX0_IRQHandler`)→ring, polled TX, bus-off recovery (§5.8.2) |
| `src/chademo.c/.h` | CHAdeMO message layer: RX H100/H101/H102 parse (byte→field per `analyze87`), periodic H108/H109 standby TX (H108 byte1-2 = measured `outvol`, 450-clamped), per-message + whole-bus watchdog timestamps (§5.18) |
| `src/spi4.c/.h` | SPI4 external-flash read transport: `CR1=0x344` (mode0/master//2/8bit/MSB), CS=PE11, SCK/MISO/MOSI=PE12/13/14 AF5; READ `0x03` + 24-bit addr (§5.21, `analyze88`) |
| `src/nv_cal.c/.h` | read + validate the stock factory HV cal record from SPI4 offset `0xFE000` (magic `0x41444A67`, 16-word additive checksum); exposes `raw_hi/raw_lo/eng_hi/eng_lo` (§5.21) |
| `src/adc.c/.h` | HV ADC front-end: ADC1 8×ch8 (PB0) + ADC2 8×ch9 (PB1) regular-simultaneous (`CCR=0x2A006`), DMA2 stream0 circular (`CR=0x5518`), TIM8 125 kHz trigger; `DMA2_Stream0_IRQHandler` (IRQ56) accumulates the PB0−PB1 differential over 3125 events → `live_raw` (§5.21) |
| `src/hv.c/.h` | `hv_init` (spi4+nv_cal+adc); `get_hv` two-point interpolation `eng_lo+(live_raw−raw_lo)(eng_hi−eng_lo)/(raw_hi−raw_lo)`; `outvol=get_hv()/10` (§5.21) |
| `src/charge_stm.c/.h` | **inert** CHAdeMO charge state machine (shadow): safe-charge sequence 13→…→30 + stop/shutdown skeleton, byte-exact state-17 engagement guard (`charge_stm_engage_ok`), interlocks + CAN watchdogs; records `STM_ACT_*` but drives no GPIO; EVSE-side inputs safe-stubbed (§5.17, `analyze80`) |
| `test_charge_stm.c` | host unit test (gcc, no hardware): engagement-guard window/thresholds + unsigned wrap, sequence walk/stall/engagement, interlocks, C009-mismatch never-engages — 47 checks |
| `src/current_ctrl.c/.h` | **inert** H102 output-current control law (shadow setpoint): state-30 `setpoint=min(request,EVSE avail)` capped by EVSE max, `target_v=min(target,limit)`, byte-exact `/1000` scale + converter `(code<7)?code:0xFF`, zero-skip keep-previous; drives no power stage; EVSE-side measurements safe-stubbed (§5.21 E, `analyze89`) |
| `test_current_ctrl.c` | host unit test (gcc, no hardware): converter/scale, min/cap law, target-voltage limit, zero-skip, EVSE-stub safety (setpoint held 0) — 42 checks |
| `main.c` | rcc→gpio_safe→hv→can→chademo→charge_stm→current_ctrl→tick→`cpsie i`, then 100 Hz loop (feed IWDG + `heartbeat` + publish `hv_*` + RX parse + `charge_stm_step` [publish `stm_*`] + `current_ctrl_step` in state-30 [publish `cc_*`] + periodic TX + can_service); no asserted power drive |
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
(offset `0x3C`) must point to `tick.c`'s strong `SysTick_Handler`, the CAN1_RX0 vector
(IRQ20, offset `0x90`) to `can.c`'s strong `CAN1_RX0_IRQHandler`, and the DMA2_Stream0 vector
(IRQ56, offset `0x120`) to `adc.c`'s strong `DMA2_Stream0_IRQHandler` (all override the weak aliases).
`hv.c`'s 64-bit `get_hv` division links `__aeabi_ldivmod` from libgcc (`-lgcc` in `build.sh`).

**Host unit test** (no hardware — verifies the charge-stm engagement guard + sequence + interlocks):

```sh
nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_charge_stm test_charge_stm.c src/charge_stm.c && ./test_charge_stm'
```

Expected: `47 checks, 0 failures`. `charge_stm.c` is pure logic (no hardware registers), so it compiles
and runs on the host; the CAN bus-freshness helper is stubbed in the test.

**Host unit test** (no hardware — verifies the H102 current-control converter/scale + min/cap law):

```sh
nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_current_ctrl test_current_ctrl.c src/current_ctrl.c && ./test_current_ctrl'
```

Expected: `42 checks, 0 failures`. `current_ctrl.c` is pure logic (no hardware registers), so it compiles
and runs on the host.

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
   **H108 (0x108) / H109 (0x109)** frames every 100 ms with standby status, and the app parses
   injected H100/H101/H102. **No contactor should click and no HV should appear** — if anything
   energises, stop immediately.
4. **Verify the HV measurement** (still no power drive): read `&hv_cal_ok` over SWD — `1` means the
   stock factory cal was read from external SPI flash; `0` means absent/invalid (`outvol` reports 0).
   With a known safe voltage applied to the HV sense input (PB0/PB1 divider), compare `&hv_outvol`
   (volts) — or H108 byte1-2 (450-clamped) on the CAN bench — against a reference meter. `&hv_adc_raw`
   is the raw differential accumulation. **`outvol` must match the reference before the gated
   engagement/power layer is allowed to use it.**
5. **Confirm the charge stm is inert**: read `&stm_state` over SWD — with the EVSE-side inputs stubbed it
   should sit at `0` (idle, no plug-in) and never advance to engagement; `&stm_engage` stays `0` and
   `&stm_action` is `0`/`6` (none/all-off). Injecting H102 with a fault byte should move `&stm_interlock`
   and force a safe stop state if the machine were active. **No GPIO is driven by the state machine** —
   `&stm_action` is a *recorded intent*, not an output. Any contactor click here is a fault — stop.
6. **Confirm the current control is inert**: read `&cc_setpoint` over SWD — with the EVSE-side measurements
   stubbed it stays `0` (the `min(request,0)==0` zero-skip), as do `&cc_cap`/`&cc_target_v` until state-30.
   `current_ctrl_step` only runs in CurrentDemand (state 30) and **drives no power stage** — `cc_*` are
   *shadow setpoints*, not outputs. No current command reaches the power stage; any energisation is a fault.

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

**Done (safe bootstrap + CAN1 message layer + HV measurement + inert charge stm + inert current control):**
- Clocks — `rcc_init` restores SYSCLK 168 MHz (§5.8.1).
- §5.20 — 100 Hz SysTick OS tick + 100 kHz TIM2 timebase (`src/tick.c`).
- §5.5c — GPIO **safe-state** init (`src/gpio.c`, active levels via `analyze86`): all power pins
  de-asserted, contactors open. (Asserted drive is a later, gated layer.)
- §5.8.2/§5.18 — CAN1 transport (`src/can.c`, 500k) + CHAdeMO message layer (`src/chademo.c`):
  RX H100/H101/H102 parse (byte→field via `analyze87`), periodic H108/H109 **standby** TX (H108
  byte1-2 = measured `outvol`, 450-clamped), per-message + whole-bus watchdog timestamps.
- §5.21 — `get_hv` **HV measurement**, faithful replica via `analyze88` (`src/spi4.c`/`nv_cal.c`/
  `adc.c`/`hv.c`): SPI4 reads the **stock factory cal from external flash** (offset `0xFE000`,
  magic + 16-word checksum — untouched by app flashing, so no bench cal needed), ADC1+ADC2
  simultaneous (PB0/PB1) + TIM8-triggered DMA2 accumulate the differential `live_raw` (3125
  events), `get_hv` interpolates → `outvol=get_hv()/10`. **Measurement only, no power drive.**
  Bench-verify `outvol` against a reference before the gated engagement/power layer relies on it.
- §5.17 — **inert charge state machine** (`src/charge_stm.c`, shadow controller via `analyze80`):
  safe-charge sequence 13→14→15→16→17→18→19→20→30 + stop/shutdown skeleton, the **byte-exact state-17
  engagement guard** (`outvol ∈ [ress_vol−10, ress_vol+5]` unsigned + dwell≥250 + isolation==4 + flag==1),
  safety interlocks + CAN watchdogs (whole-bus 1525 / per-message 100). Records `STM_ACT_*` but drives
  **no GPIO**; EVSE-side handshake inputs safe-stubbed until the CCS2 PLC/DIN layer. Host-unit-tested
  (`test_charge_stm.c`, 47 checks). **No power drive.**
- §5.21 E — **inert H102 current control** (`src/current_ctrl.c`, shadow setpoint via `analyze89`): the
  byte-exact state-30 CurrentDemand law `setpoint = min(H102.ChargingCurrentRequest, EVSE avail)` capped by
  the EVSE max-current (`cap!=0`), `target_v = min(H102.TargetBatteryVoltage, p[+0x216] limit)`, with the
  `/1000` scaling (`muls`+`udiv`) + converter `0x0804E786` (`(code<7)?code:0xFF`) and the zero-skip
  keep-previous paths. Corrects the earlier `setpara(4)`/`[+0x44]→[+0x40]` sketch (C013 `setpara` is a
  validation stub; the law is inline in state-30, context `0x20000780` `+0x16…+0x1e`). Runs only in state-30;
  EVSE-side measurements safe-stubbed 0 → setpoint held 0. Host-unit-tested (`test_current_ctrl.c`, 42
  checks). **No power drive.**

**Remaining layers:**
- CCS2 EVSE-side subsystem (PLC/QCA7005 + DIN70121/ISO15118) — supplies the stm's EVSE-side handshake
  inputs (isolation / precharge_flag / CableCheck / ChargeParameterDiscovery) **and** the current-control
  EVSE-side measurements (max/available current + range-code factors, voltage limit) currently safe-stubbed.
- §5.5c — **asserted** power-stage drive (PB10/PB11 precharge, PD8 inner contactor, PC9 charge,
  PE7/PE8 d1/d2, PD3/PE4 e-lock) — **LAST**, behind a compile-time safety flag, drive **only** once
  the controller is bench-validated.