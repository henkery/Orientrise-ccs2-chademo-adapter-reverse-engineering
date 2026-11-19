# custom_fw — inert custom-app skeleton (Orientrise KM-CCS2CHAdeMO-1)

A **minimal, flashable, stock-reversible** custom application for the adapter
(STM32F427/F429, Cortex-M4). It exists to prove the full **build → wrap → flash → recover**
pipeline end-to-end on the byte-derived memory layout (REPORT §5.19) and boot entry contract
(§5.15/§5.16). **It is NOT a charge controller.**

## Safety — read first

This skeleton is **inert**:

- It performs **no GPIO writes** and enables **no peripheral that could energise the power
  stage**. All contactor / precharge / charge / e-lock pins stay at their reset state
  (analog input) ⇒ **contactors open, no HV output**.
- The only peripheral register it touches is the **IWDG key register** (`0x40003000`, a
  watchdog feed). This is harmless whether or not the watchdog is enabled: if the bootloader
  left the IWDG running, feeding it keeps the app alive (no reset loop); if not, it is a no-op.
- A RAM `heartbeat` counter increments each loop so you can confirm "the custom app is
  running" over SWD **without any external side effect**.

Do **not** add power-stage GPIO control until the charge controller is implemented and
bench-validated against the decoded laws (REPORT §5.17 state machine + engagement guard +
interlocks, §5.18 H108/H109 output, §5.20 100 Hz timebase, §5.21 `get_hv` measurement + H102
current control, §5.5c GPIO map).

## Files

| file | purpose |
|---|---|
| `linker.ld` | GNU ld script: FLASH `0x08020000` 640K (app sectors 5–9), RAM `0x20000000` 192K, CCM `0x10000000` 64K, `_estack=0x20030000` (§5.19) |
| `startup.s` | vector table + self-bootstrapping `Reset_Handler`: MSP from `vector[0]`, `VTOR=0x08020000`, copy `.data`, zero `.bss`+CCM, call `main` (the boot writes no MSP/VTOR, §5.15/§5.16) |
| `main.c` | inert loop: feed IWDG + bump `heartbeat` + idle |
| `build.sh` | builds via `nix-shell -p gcc-arm-embedded python3` → `app.elf`/`app.bin`, verifies vectors, pads to sector 5 |
| `verify_pad.py` | checks `vector[0]==0x20030000`, `vector[1]` is an in-app Thumb address; pads `app.bin` → `app_padded.bin` (128 KB, `0xFF` tail) |

Build outputs (`app.elf`, `app.map`, `app.bin`, `app_padded.bin`) are git-ignored.

## Build

```sh
bash build.sh
```

Produces `app.bin` (vectors + code, linked at `0x08020000`) and `app_padded.bin` (128 KB =
sector 5, matching the ground-truth `app5.bin` dump). Expected vectors:
`MSP=0x20030000`, `reset=0x08020041` (handler `0x08020040`, Thumb bit set).

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
3. The app idles feeding the IWDG. Confirm it runs over SWD: halt and read `&heartbeat`
   (incrementing) or check `PC` is in the `main` loop (`0x080200xx`). **No contactor should
   click and no HV should appear** — if anything energises, stop immediately.

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

Implement, on this layout, the decoded mechanisms:
- §5.20 — 100 Hz OS tick timebase (TIM1/2/3 100 kHz free-running; software tick counter).
- §5.21 — `get_hv` measurement (Vrefint-calibrated ADC → NV two-point cal → `outvol=get_hv()/10`)
  and the H102 vehicle-request → output-current control law (`setpara(4)`, struct `0x20000780`).
- §5.17 — CHAdeMO charge state machine + state-17 voltage-engagement guard
  (`outvol ∈ [ress_vol−10, ress_vol+5]`) + safety interlocks + CAN watchdogs.
- §5.18 — H108/H109 charger-status reporting (/1000 scaling, 450 clamp, bit-reversal).
- §5.5c — power-stage GPIO (PB10/PB11 precharge, PD8 inner contactor, PC9 charge, PE7/PE8 d1/d2,
  PD3/PE4 e-lock) — drive these **only** once the controller is validated.