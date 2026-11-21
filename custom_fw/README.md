# custom_fw — safe-bootstrap + CAN1 message layer + HV measurement + inert charge stm + inert current control + CCS2 EVCC subsystem (Orientrise KM-CCS2CHAdeMO-1)

A **minimal, flashable, stock-reversible** custom application for the adapter
(STM32F427/F429, Cortex-M4), being built up in incremental, independently-testable layers
toward a safe CHAdeMO charge controller. It proves the full **build → wrap → flash → recover**
pipeline end-to-end on the byte-derived memory layout (REPORT §5.19) and boot entry contract
(§5.15/§5.16). **Current stage: SAFE BOOTSTRAP + CAN1 MESSAGE LAYER + HV MEASUREMENT + INERT CHARGE
STM + INERT CURRENT CONTROL + CCS2 EVCC SUBSYSTEM** — clocks + timebase + GPIO safe-state + CAN1
(500k) CHAdeMO RX/TX + the factory-calibrated HV measurement front-end (`get_hv` → `outvol`) + the inert
charge state machine (safe-charge sequence + byte-exact state-17 engagement guard + interlocks + CAN
watchdogs) + the inert H102 output-current control law (state-30 `min(request, EVSE avail)` setpoint capped
by EVSE max) + the **CCS2 EVSE-side (EVCC) subsystem**: QCA7005 PLC SPI1 transport → SLAC ISO15118-3
matching → CP/PP signaling → SDP/V2GTP discovery → DIN70121 measurement + CurrentDemand actuation, glued by
the `ccs2` controller. The CCS2 subsystem supplies the charge-stm EVSE handshake inputs + the current-control
EVSE measurements + the `CurrentDemandReq` actuation image. It performs **no asserted power-stage drive** —
the state machine and current control are *shadow* controllers that record but do not execute power actions,
and the CCS2 subsystem is communication only. The DIN EXI bit-grammar codec + the autonomous session
state-machine timers/retries (`analyze93`, `src/exi.c`/`src/din_session.c`) **and the live UDP/TCP/IPv6 +
mbedTLS transport carriage** (`analyze94`, `src/v2g_net.c`) are now **recovered and built**; the lwIP TCP
reliability + mbedTLS crypto third-party stacks are represented by hooks, and the CP/PP analog front-end stays
GATED until recovered/bench-validated.

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
  ress_vol+5] && dwell≥250`; the EVSE-side handshake inputs (isolation/precharge_flag/plug_in/…) are now
  **supplied by the CCS2 EVCC controller** (`ccs2_evse()`, §5.9) — with the CP front-end stubbed unplugged
  and no live network transport they hold 0, so the machine holds in the early states and **cannot
  engage**. Interlocks (whole-bus 1525-tick / per-message 100-tick CAN watchdogs, H102 fault,
  emergency, bms/hw fault, CurrentDemand isolation==3) force a safe stop state. Host-unit-tested
  (`test_charge_stm.c`, 47 checks). State/interlock/engage/action are SWD-readable (`stm_*`).
- **Inert H102 current control**: `current_ctrl_step` runs the C013 state-30 CurrentDemand output-current
  law (§5.21 E, `analyze89`; converter corrected by `analyze92`) as a **shadow setpoint** — `setpoint =
  min(H102.ChargingCurrentRequest, EVSE available)` capped by the EVSE max-current, `target_v =
  min(H102.TargetBatteryVoltage, limit)`, with the byte-exact `/1000` scaling + converter `0x0804E786` =
  **power-of-10 TABLE[code]** for code∈[0,6] else 0xFF (real value = raw·10^(factor−3); corrects the earlier
  `(code<7)?code:0xFF` mis-decode — delegates to `din_pow10`/`din_scale`). It **drives no power stage** (no
  GPIO/DAC/PWM). The EVSE-side measurements (max/available current + pow10 factors, voltage limit) are now
  **supplied by `ccs2_fill_current_ctrl()`** from the DIN70121 measurement struct (§5.9); until a live
  `CurrentDemandRes` is decoded they hold 0, so `avail==0` and the `min(request,0)==0` zero-skip **holds the
  setpoint at 0** — no current is ever commanded. It only runs in state-30 (CurrentDemand). Host-unit-tested
  (`test_current_ctrl.c`, 46 checks). Setpoint/cap/target are SWD-readable (`cc_*`).
- **CCS2 QCA7005 PLC transport**: `qca7005_init` brings up the QCA7005 HomePlug GreenPHY PLC modem over
  SPI1 (§5.9 transport addendum, `analyze91`) — PA5/6/7 AF5, CS=PA4, reset=PC5, IRQ=PC4 polled, `CR1=0x0357`
  (Mode 3 /8 master), the SPI register protocol (`0xC000|addr` read / `0x4000|addr` write), reg-init
  (sig `0xAA55` + `0x1200=0xC5B`/`0xC00=0x447`/`0xD00=0x41`), the `0xAA`/`0x55`-framed buffer TX/RX, and the
  MAC-read MME (`0xA000`/`0xA001`) to resolve the modem PIB MAC. `qca7005_service` polls the modem + drains
  RX frames to a callback. This is **communication only** — it drives no power pin (only SPI1 + GPIOA CS +
  GPIOC reset/IRQ). The bring-up is blocking but **IWDG-fed**; if no modem is present it times out (~4 s)
  and reports `ccs2_qca_ok=0`, and the app continues. The SLAC/SDP/DIN session layers above it are now
  built (next bullet). Host-unit-tested (`test_qca7005.c`, 26 checks). `ccs2_qca_ok`/`ccs2_mac_valid`/
  `ccs2_rx_frames` are SWD-readable.
- **CCS2 EVCC subsystem (SLAC + CP/PP + SDP/V2GTP + DIN70121)**: above the transport, `ccs2_init` brings up
  the EVSE-side subsystem (§5.9 upper-layer addendum, `analyze92`) — `slac` (ISO15118-3 matching SM → NID/NMK/
  EVSE-MAC/link-up), `cp` (CP/PP scaling + CP-state + duty-5 + PP plug-in hysteresis/debounce; BCB recorded
  only), `sdp`/`v2gtp` (SECC discovery + security select + appHandshake protocol select), `din70121`
  (measurement struct + pow10 converter/scale + CurrentDemandRes decode + EV-target setter + CurrentDemandReq
  encode + **EXI grammar messages**), `exi` (**EXI bit-level codec**, `analyze93` E: byte-exact MSB-first
  read/write bits + varlen + signed + octet + PhysicalValueType wire order + framing), `din_session`
  (**autonomous DIN session SM**, `analyze93` F: state enum 0..13 + timers 4000/120000/150000/40000/14000 ms +
  retry cap 20 + CD modulo cadence + FAILED→shutdown + fault post — inert), glued by `ccs2` (RX EtherType
  dispatch + session sequencing driving `din_session_step`). `ccs2_evse()` supplies the charge-stm
  EVSE handshake inputs (sourced from the session SM while active); `ccs2_fill_current_ctrl()` supplies the
  current-control EVSE measurements; `ccs2_demand(setpoint)` encodes the `CurrentDemandReq` EXI image (the
  asserted current drive is realized upstream as this CCS2 PLC message — §5.21 F — not a local PWM/DAC). This
  is **communication only** — the pure-logic modules drive **no power pin** (disasm-verified, `verify_ccs2.py`).
  The EXI grammar + session timers (`analyze93`) **and the live UDP/TCP/IPv6 + mbedTLS transport carriage**
  (`analyze94`, `src/v2g_net.c`) are **recovered/built**: `ccs2_rx` routes IPv6 → `v2g_net_rx_ethernet`
  (UDP→SDP / TCP→deframe→`ccs2_rx_exi`), `ccs2_step` drives the transport SM + starts TCP at SDP-done. The lwIP
  TCP reliability + mbedTLS crypto are gated third-party **hooks**; the CP/PP analog front-end acquisition is
  still gated, so `cp_step` is fed a safe "unplugged" stub (plug_in=0) and the EVSE inputs hold 0; the
  session-flag setters allow bench injection. In CurrentDemand the `CurrentDemandReq` image is produced
  (`ccs2_cd_req`/`ccs2_cd_req_len`) and sent via `v2g_net_tcp_send` — **inert**: it only transmits when the
  transport is ESTABLISHED (gated TCP connect/TLS handshake), so nothing is commanded in normal operation.
  Host-unit-tested (`test_{v2gtp,slac,cp,sdp,din70121,ccs2,exi,din_session,v2g_net}.c`,
  14/54/32/31/36/21/55/39/89 checks; full suite 490). `ccs2_st`/`ccs2_link`/`ccs2_secc`/`ccs2_proto` +
  `din_st_state`/`din_st_fault`/`din_st_retry`/`din_st_active` + `v2g_net_st`/`v2g_net_mode`/`v2g_net_rx`/
  `v2g_net_tx` are SWD-readable.
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
| `src/charge_stm.c/.h` | **inert** CHAdeMO charge state machine (shadow): safe-charge sequence 13→…→30 + stop/shutdown skeleton, byte-exact state-17 engagement guard (`charge_stm_engage_ok`), interlocks + CAN watchdogs; records `STM_ACT_*` but drives no GPIO; EVSE-side inputs from `ccs2_evse()` (§5.17, `analyze80`) |
| `test_charge_stm.c` | host unit test (gcc, no hardware): engagement-guard window/thresholds + unsigned wrap, sequence walk/stall/engagement, interlocks, C009-mismatch never-engages — 47 checks |
| `src/current_ctrl.c/.h` | **inert** H102 output-current control law (shadow setpoint): state-30 `setpoint=min(request,EVSE avail)` capped by EVSE max, `target_v=min(target,limit)`, byte-exact `/1000` scale + converter `0x0804E786`=pow10 TABLE[code] (corrects analyze89; delegates to `din_pow10`/`din_scale`), zero-skip keep-previous; drives no power stage; EVSE measurements from `ccs2_fill_current_ctrl()` (§5.21 E, `analyze89`/`analyze92`) |
| `test_current_ctrl.c` | host unit test (gcc, no hardware): pow10 converter/scale, min/cap law, target-voltage limit, zero-skip, EVSE-stub safety (setpoint held 0) — 46 checks |
| `src/qca7005.c/.h` | QCA7005 PLC SPI1 host driver + MME/Ethernet transport: `CR1=0x0357` (Mode 3/master//8/8bit/MSB/SSM), CS=PA4, reset=PC5, IRQ=PC4 polled; reg read `0xC000\|addr` / write `0x4000\|addr`; reg-init (sig `0xAA55` + `0x1200=0xC5B`/`0xC00=0x447`/`0xD00=0x41`); `0xAA`/`0x55`-framed buffer TX/RX; MAC-read MME `0xA000`/`0xA001`; 4096 B RX ring + per-frame callback; communication only, no power GPIO (§5.9, `analyze91`) |
| `test_qca7005.c` | host unit test (gcc, no hardware): MAC-read REQ build, MAC-read CNF validation, RX packet-header parse math — 26 checks |
| `src/v2gtp.c/.h` | V2GTP framing: encode/parse `01 FE type BE len BE`; types `0x8001` EXI / `0x9000` SDP-req / `0x9001` SDP-res (§5.9, `analyze92`) |
| `src/slac.c/.h` | ISO15118-3 SLAC matching SM + MME builders/validators (PARM/ATTEN/SOUND/MATCH/SET_KEY) + PRNG LCG → NID/NMK/EVSE-MAC/link-up; communication only (§5.9, `analyze92`) |
| `src/cp.c/.h` | CP/PP analog signaling: scaling getters (`AD_PP`/`AD_CPD`/CP), CP-state char, duty-5 detector, PP plug-in hysteresis+4-debounce; BCB recorded only (gated); CP front-end acquisition gated (§5.9, `analyze92`) |
| `src/sdp.c/.h` | SECC Discovery SM + security select (low-byte cert-count test) + SDP req/res build/validate/parse + appHandshake protocol select (DIN/ISO); **TLS wire labels corrected** (`SDP_SECURITY_TLS=0x00`/`NONE=0x10`, `use_tls=(secc_security==0)`); UDP send via `v2g_net_udp_send` (§5.9, `analyze92`/`analyze94`) |
| `src/din70121.c/.h` | DIN70121 measurement struct + pow10 converter/scale (`0x0804E786` correction) + CurrentDemandRes decode + EV-target setter (arm 0x606) + CurrentDemandReq encode + **EXI grammar messages** (CurrentDemandRes complete 10-field / CableCheck / PreCharge / SessionStop decode + CurrentDemandReq grammar encode) (§5.9, `analyze92`/`analyze93`) |
| `src/exi.c/.h` | **EXI bit-level codec** (`analyze93` E): byte-exact MSB-first readBits/writeBits + varlen u16/u32 + signed ones-complement + octet + PhysicalValueType wire order (Multiplier,Unit,Value) + V2GTP/0x80/7-bit-event framing; pure logic, no power GPIO (§5.9) |
| `src/din_session.c/.h` | **autonomous DIN session SM** (`analyze93` F, inert): state enum 0..13 + timers 4000/120000/150000/40000/14000 ms (global vs engagement-phase) + retry cap 20 + CD modulo cadence + FAILED→shutdown + fault post (records code, drives no GPIO); Req images via a TX hook → `v2g_net_tcp_send` (§5.9) |
| `src/ccs2.c/.h` | CCS2 EVCC controller glue: RX EtherType dispatch (MME→SLAC, **IPv6→`v2g_net_rx_ethernet`**) + session sequencing driving `din_session_step` + transport SM (`v2g_net_step`/`start_tcp`) + `ccs2_evse()` handshake outputs (sourced from the session SM while active) + `ccs2_fill_current_ctrl()` EVSE measurements + `ccs2_demand()` CurrentDemandReq actuation image + `ccs2_rx_exi()` decoded-Res entry (fed by the live transport) + session-flag setters (bench injection); communication only, no power GPIO (§5.9, `analyze92`/`analyze93`/`analyze94`) |
| `src/v2g_net.c/.h` | **live UDP/TCP/IPv6 + mbedTLS transport carriage** (`analyze94` G/H, inert): EUI-64 link-local from PIB MAC + mcast MAC, IPv6/UDP/TCP header build/parse, Internet + pseudo-header checksum, Ethernet framing, V2GTP stream deframe, **TLS decision (TLS iff SECC security byte==0; wire 0x00=TLS/0x10=No-TLS)** + mbedTLS config record (cipher list {0xC023,0xC025}, authmode 2), transport SM (connect 30000ms / idle≥300 close / TLS handshake), RX demux→SDP/EXI dispatch→`ccs2_rx_exi`, TX UDP/TCP send via hooks, 16×128B diagnostic trace ring; lwIP TCP reliability + mbedTLS crypto are gated third-party hooks; no power GPIO (§5.9) |
| `test_v2g_net.c` | host unit test (gcc, no hardware; `ccs2_rx_exi`/`sdp_rx` spied): EUI-64/mcast MAC, IPv6/UDP/TCP build/parse, Internet checksum vector, TLS decision, V2GTP deframe (single/multi/partial/byte-by-byte), transport SM (plain/TLS/idle/timeout), EXI dispatch, RX UDP/TCP demux, TX framing — 89 checks |
| `test_v2gtp.c` / `test_slac.c` / `test_cp.c` / `test_sdp.c` / `test_din70121.c` / `test_ccs2.c` / `test_exi.c` / `test_din_session.c` | host unit tests (gcc, no hardware; QCA7005 stubbed where needed): V2GTP framing 14, SLAC sequence walk 54, CP/PP scaling/state/plug 32, SDP security/req/res/protocol 31, DIN pow10/CD-res/CD-req 36, CCS2 integration 21, EXI primitives/PVT/framing 55, session sequence/timers/retry/cadence/faults 39 checks (full suite 490 with `test_v2g_net` 89) |
| `main.c` | rcc→gpio_safe→hv→can→chademo→charge_stm→current_ctrl→tick→`cpsie i`→qca7005_init→ccs2_init→`v2g_net_set_local_mac` [EUI-64 from PIB MAC], then 100 Hz loop (feed IWDG + `heartbeat` + publish `hv_*` + RX parse + cp_step [unplugged stub] + ccs2_step [drives din_session_step + v2g_net_step] + `charge_stm_step` with EVSE inputs from `ccs2_evse()` [publish `stm_*`] + `current_ctrl_step` in state-30 from `ccs2_fill_current_ctrl()` [publish `cc_*`] + `ccs2_demand` inert CD-req image + `v2g_net_tcp_send` [inert, only when ESTABLISHED; publish `ccs2_cd_req*`] + periodic TX + can_service + `qca7005_service`→ccs2_rx [publish `ccs2_*`] + `din_session_get` [publish `din_st_*`] + `v2g_net_get` [publish `v2g_net_st/mode/rx/tx`]); no asserted power drive |
| `build.sh` | builds via `nix-shell -p gcc-arm-embedded python3` → `app.elf`/`app.bin`, verifies vectors, pads to sector 5 |
| `verify_pad.py` | checks `vector[0]==0x20030000`, `vector[1]` is an in-app Thumb address; pads `app.bin` → `app_padded.bin` (128 KB, `0xFF` tail) |
| `verify_ccs2.py` | disasm-verifies the built CCS2/EXI/session/transport modules: presence of wired symbols (incl. `din_session_*` + `v2g_net_*`), **power-GPIO safety** (no peripheral base `0x400xxxxx` referenced in the pure-logic modules), main integration calls (incl. `din_session_get`/`v2g_net_get`/`v2g_net_tcp_send`), pow10 converter table + the five session timer constants + retry cap 20 + transport cipher list {0xC023,0xC025} + IPv6 EtherType/next-header demux (−O2-inlined helpers verified via constants); reports bench-only APIs gc-eliminated from the autonomous image — 56 checks |

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

**Host unit test** (no hardware — verifies the H102 current-control pow10 converter/scale + min/cap law):

```sh
nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_current_ctrl test_current_ctrl.c src/current_ctrl.c src/din70121.c src/exi.c && ./test_current_ctrl'
```

Expected: `46 checks, 0 failures`. `current_ctrl.c` is pure logic (no hardware registers); the converter
delegates to `din_pow10`/`din_scale` in `din70121.c` (linked here, with `exi.c` for the grammar codec).

**Host unit test** (no hardware — verifies the QCA7005 MAC-read REQ build + CNF validation + RX packet parse):

```sh
nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_qca7005 test_qca7005.c src/qca7005.c && ./test_qca7005'
```

Expected: `26 checks, 0 failures`. The pure helpers (frame build / CNF validation / packet-header parse)
compile and run on the host; the SPI hardware paths are disasm-verified separately and `tick_delay_ms` is
stubbed in the test.

**Host unit tests** (no hardware — verify the CCS2 EVCC upper layers; QCA7005 stubbed where needed):

```sh
nix-shell -p gcc --run '
gcc -O2 -Wall -Wextra -Isrc -o test_v2gtp     test_v2gtp.c     src/v2gtp.c                       && ./test_v2gtp
gcc -O2 -Wall -Wextra -Isrc -o test_slac      test_slac.c      src/slac.c                        && ./test_slac
gcc -O2 -Wall -Wextra -Isrc -o test_cp        test_cp.c        src/cp.c                          && ./test_cp
gcc -O2 -Wall -Wextra -Isrc -o test_sdp       test_sdp.c       src/sdp.c src/v2gtp.c             && ./test_sdp
gcc -O2 -Wall -Wextra -Isrc -o test_din70121  test_din70121.c  src/din70121.c src/exi.c          && ./test_din70121
gcc -O2 -Wall -Wextra -Isrc -o test_exi       test_exi.c       src/exi.c                         && ./test_exi
gcc -O2 -Wall -Wextra -Isrc -o test_din_session test_din_session.c src/din_session.c src/din70121.c src/exi.c && ./test_din_session
gcc -O2 -Wall -Wextra -Isrc -o test_ccs2      test_ccs2.c      src/ccs2.c src/slac.c src/sdp.c src/cp.c src/din70121.c src/exi.c src/din_session.c src/v2gtp.c src/v2g_net.c && ./test_ccs2
gcc -O2 -Wall -Wextra -Isrc -o test_v2g_net   test_v2g_net.c   src/v2g_net.c src/v2gtp.c         && ./test_v2g_net
'
```

Expected: `14 / 54 / 32 / 31 / 36 / 55 / 39 / 21 / 89 checks, 0 failures` respectively (full suite **490**).
`test_slac.c` and `test_ccs2.c` provide their own `qca7005_frame_send`/`qca7005_mac` stubs (do **not** link
`src/qca7005.c` into those — it collides with the stubs); `test_ccs2.c` also stubs `tick_get`. `test_din70121.c`/
`test_ccs2.c`/`test_current_ctrl.c` link `src/exi.c` (the din70121 grammar codec references the EXI primitives);
`test_ccs2.c` also links `src/din_session.c` + `src/v2g_net.c` (the autonomous session SM + live transport
carriage wired into `ccs2_step`/`ccs2_rx`). `test_v2g_net.c` spies `ccs2_rx_exi`/`sdp_rx` (does not link the heavy
ccs2/sdp/din modules). The pure protocol/scaling/measurement/codec/session/transport logic compiles and runs on
the host; the lwIP TCP reliability + mbedTLS crypto + SPI paths are gated/disasm-verified separately.

**Built-image disasm verification** (power-GPIO safety + presence + pow10 table + transport constants):

```sh
nix-shell -p gcc-arm-embedded python3 python3Packages.capstone --run 'python3 verify_ccs2.py'
```

Expected: `56 checks, 0 failures` — confirms the wired CCS2/EXI/session/transport symbols are linked, the
pure-logic modules reference **no** peripheral base `0x400xxxxx` (no power GPIO), `main` calls the integration
functions (incl. `din_session_get`/`v2g_net_get`/`v2g_net_tcp_send`/`v2g_net_set_local_mac`), the pow10 converter
table is present, the five session timer constants (4000/120000/150000/40000/14000) + retry cap 20 are compiled
into `din_session`, and the transport cipher list {0xC023,0xC025} + IPv6 EtherType (0xDD86 LE) + next-header
UDP 17/TCP 6 demux are compiled into `v2g_net` (the small helpers are −O2-inlined into their callers, verified via
constants). Bench-only APIs gc-eliminated from the autonomous image are reported informationally (host-tested
above); the live `v2g_net` RX path now reaches the EXI decode chain (`ccs2_rx_exi`/`exi_decode_header`/
`din_session_rx`/`v2gtp_parse`), so those are retained.

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
7. **Confirm the QCA7005 PLC transport is communication-only**: read `&ccs2_qca_ok` over SWD — `1` means the
   QCA7005 modem answered the CPU-ready signature (`0xAA55`) and its PIB MAC was read (`&ccs2_mac_valid=1`);
   `0` means no modem / timeout (the app still runs). `&ccs2_rx_frames` counts Ethernet frames received from
   the modem. The transport touches only SPI1 + PA4 (CS) + PC5 (reset) + PC4 (IRQ) — **no power pin**. With
   no PLC modem connected the bring-up times out (~4 s, IWDG-fed) and reports failure; the heartbeat then
   increments normally. **No contactor should click** — the PLC transport drives no power stage.
8. **Confirm the CCS2 EVCC subsystem is communication-only**: read `&ccs2_st` over SWD — with the CP
   front-end stubbed unplugged (`plug_in=0`) it sits at `0` (IDLE) and never advances to SLAC/SDP/session;
   `&ccs2_link`/`&ccs2_secc` stay `0`. The pure-logic modules (slac/cp/sdp/din70121/exi/din_session/ccs2/
   v2gtp) reference **no peripheral base** (disasm-verified, `verify_ccs2.py`) — they drive no power pin. In
   CurrentDemand the `CurrentDemandReq` EXI image is produced (`&ccs2_cd_req_len=108`, `&ccs2_cd_req[0..107]`)
   and sent via `v2g_net_tcp_send` — **inert**: it only transmits when the transport is ESTABLISHED (gated TCP
   connect/TLS handshake), so nothing is commanded to the EVSE in normal operation. The EXI grammar + autonomous
   session sequence/timers (`analyze93`; `&din_st_state`/`&din_st_fault`) **and the live transport carriage**
   (`analyze94`; `&v2g_net_st`/`&v2g_net_mode`/`&v2g_net_rx`/`&v2g_net_tx`) are recovered/built; the lwIP TCP
   reliability + mbedTLS crypto are gated hooks and the CP analog acquisition is still gated, so the session
   holds idle and the session-flag setters allow bench injection for testing the downstream charge-stm/
   current-control wiring. **No contactor should click and no HV should appear** — the CCS2 subsystem is
   communication only.

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

**Done (safe bootstrap + CAN1 message layer + HV measurement + inert charge stm + inert current control + CCS2 EVCC subsystem [QCA7005 transport + SLAC + CP/PP + SDP/V2GTP + DIN70121 + EXI codec + autonomous session SM]):**
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
  **no GPIO**; EVSE-side handshake inputs now from `ccs2_evse()` (hold 0 with CP stubbed unplugged +
  no live network transport). Host-unit-tested (`test_charge_stm.c`, 47 checks). **No power drive.**
- §5.21 E — **inert H102 current control** (`src/current_ctrl.c`, shadow setpoint via `analyze89`, converter
  corrected by `analyze92`): the byte-exact state-30 CurrentDemand law `setpoint = min(H102.ChargingCurrentRequest,
  EVSE avail)` capped by the EVSE max-current (`cap!=0`), `target_v = min(H102.TargetBatteryVoltage, p[+0x216]
  limit)`, with the `/1000` scaling (`muls`+`udiv`) + converter `0x0804E786` = **power-of-10 TABLE[code]**
  (code∈[0,6] else 0xFF; real value = raw·10^(factor−3) — corrects the analyze89 `(code<7)?code:0xFF`
  mis-decode; delegates to `din_pow10`/`din_scale`) and the zero-skip keep-previous paths. Corrects the earlier
  `setpara(4)`/`[+0x44]→[+0x40]` sketch (C013 `setpara` is a validation stub; the law is inline in state-30,
  context `0x20000780` `+0x16…+0x1e`). Runs only in state-30; EVSE-side measurements now from
  `ccs2_fill_current_ctrl()` (hold 0 until a live CurrentDemandRes) → setpoint held 0. Host-unit-tested
  (`test_current_ctrl.c`, 46 checks). **No power drive.**
- §5.9 transport addendum — **CCS2 QCA7005 PLC transport** (`src/qca7005.c`, via `analyze91`): the SPI1
  host driver + MME/Ethernet TX/RX that carries the CCS2 EVCC traffic. `CR1=0x0357` (Mode 3 /8 master),
  CS=PA4 / reset=PC5 / IRQ=PC4 polled, SPI register protocol (`0xC000|addr` read / `0x4000|addr` write),
  reg-init (sig `0xAA55` + `0x1200=0xC5B`/`0xC00=0x447`/`0xD00=0x41`), `0xAA`/`0x55`-framed buffer TX/RX,
  MAC-read MME `0xA000`/`0xA001` (resolves the modem PIB MAC), 4096 B RX ring + per-frame callback.
  Corrects the C009-era anchors (C013 driver `0x08089xxx`, SPI1 primitives `0x08093Cxx–0x08093Fxx`).
  **Communication only, no power drive**; bare-metal (no RTOS mutex, IWDG-fed bring-up, RX polled from
  `qca7005_service`). Host-unit-tested (`test_qca7005.c`, 26 checks); built-image constants disasm-verified.
  The foundation the SLAC/SDP/DIN session layers build on.
- §5.9 upper-layer addendum — **CCS2 EVCC subsystem** (`src/{v2gtp,slac,cp,sdp,din70121,ccs2}.c`, via
  `analyze92`): the EVSE-side subsystem above the transport. `slac` (ISO15118-3 matching SM + MME
  builders/validators + PRNG → NID/NMK/EVSE-MAC/link-up), `cp` (CP/PP scaling + CP-state + duty-5 + PP plug-in
  hysteresis/debounce; BCB recorded only), `sdp`/`v2gtp` (SECC discovery + security select + appHandshake
  protocol select), `din70121` (measurement struct + **pow10 converter/scale** [corrects analyze89] +
  CurrentDemandRes decode + EV-target setter + CurrentDemandReq encode), `ccs2` (EVCC controller glue: RX
  EtherType dispatch + session sequencing + `ccs2_evse()` handshake outputs + `ccs2_fill_current_ctrl()` EVSE
  measurements + `ccs2_demand()` CurrentDemandReq actuation image). **Supplies** the charge-stm EVSE handshake
  inputs + the current-control EVSE measurements + the CurrentDemandReq actuation (§5.21 F). **Communication
  only, no power GPIO** (disasm-verified `verify_ccs2.py`). Host-unit-tested (`test_{v2gtp,slac,cp,sdp,
  din70121,ccs2}.c`, 14/54/32/31/36/21 checks).
- §5.9 EXI grammar + session-SM addendum — **DIN EXI codec + autonomous session SM** (`src/{exi,din_session}.c`
  + `din70121` grammar messages, via `analyze93`): the two layers the upper-layer addendum left gated. `exi`
  (byte-exact MSB-first readBits/writeBits + varlen u16/u32 + signed ones-complement + octet + PhysicalValueType
  wire order + V2GTP/0x80/7-bit-event framing; generated grammar-table-driven OpenV2G-style, 81 productions,
  **ev-map corrected** — agent-E was +2-shifted for ev≥0x0e), `din_session` (autonomous SM: state enum 0..13 +
  timers 4000/120000/150000/40000/14000 ms [global vs engagement-phase] + retry cap 20 + CD modulo cadence +
  FAILED→shutdown + fault post 0x0802C9D0→0x20000774 — **inert**, records the fault code, drives no GPIO),
  wired into `ccs2_step` (sources the EVSE handshake flags from the session SM while active) + `main` (publish
  `din_st_*`). **Communication only, no power GPIO** (disasm-verified `verify_ccs2.py`, 56 checks). Host-unit-
  tested (`test_exi.c` 55, `test_din_session.c` 39; full suite 490). The live transport that feeds `ccs2_rx_exi`
  was subsequently recovered by `analyze94` (next bullet). **Still GATED:** exact Req-side grammars / root-event
  numbering [?], DIN-vs-ISO DC_EVSEStatus layout [?], CP/PP analog front-end acquisition.
- §5.9 live-transport addendum — **UDP/TCP/IPv6 + mbedTLS transport carriage** (`src/v2g_net.c`, via `analyze94`
  G/H): the network carriage the upper layers left gated. EUI-64 link-local from the PIB MAC
  (`netif_create_ip6_linklocal_address 0x08090D68`) + mcast MAC, IPv6/UDP/TCP header build/parse
  (`ip6_output_if 0x0809BBEC` / `udp_sendto_if_src 0x0809028A` / `tcp_output_segment 0x08092A6E`), Internet +
  pseudo-header checksum, Ethernet framing, RX demux (`ethernet_input 0x0809D914` EtherType LE 0xDD86 →
  `ip6_input 0x0809B88E` next-header 6 TCP/17 UDP/58 ICMPv6/59 drop) → SDP/EXI dispatch → `ccs2_rx_exi`, V2GTP
  stream deframe, **TLS decision (TLS iff SECC security byte==0; wire 0x00=TLS/0x10=No-TLS — CORRECTED, the
  firmware log labels + prior `sdp.c` `use_tls(!=0)` were inverted)** + mbedTLS config record (cipher list
  {0xC023 ECDHE-ECDSA-AES128-CBC-SHA256, 0xC025 ECDH-ECDSA-AES128-CBC-SHA256}, authmode 2 VERIFY_REQUIRED),
  transport SM (connect 30000ms / idle≥300 close / TLS handshake), TX UDP/TCP send via hooks (send router
  0x08020338 mode1 plain/mode2 TLS), 16×128B diagnostic trace ring (live RX bypasses). Wired into `ccs2_rx`
  (IPv6→`v2g_net_rx_ethernet`), `ccs2_step` (`v2g_net_step` + `start_tcp` at SDP-done), `ccs2_init` (Ethernet TX
  hook→`qca7005_frame_send` + SDP UDP hook), `main` (`v2g_net_set_local_mac` + `v2g_net_tcp_send` + publish
  `v2g_net_*`). **Communication only, no power GPIO** (disasm-verified `verify_ccs2.py`). Host-unit-tested
  (`test_v2g_net.c` 89; full suite 490). **GATED (third-party stacks, represented by hooks):** lwIP TCP
  reliability (SYN/ACK/retransmit/congestion), mbedTLS crypto (ECDHE/AES/SHA256/X509), ND6 neighbor resolution,
  CA flash→RAM populator.

**Remaining layers:**
- CCS2 **transport third-party stacks + remaining grammar/analog gaps**: the live UDP/TCP/IPv6 + mbedTLS
  transport **glue + wire framing + protocol decisions are recovered/built** (`analyze94`, `src/v2g_net.c`);
  what stays gated is the heavy third-party code represented by hooks — lwIP TCP reliability
  (SYN/ACK/retransmit/congestion), mbedTLS crypto (ECDHE/AES/SHA256/X509), ND6 neighbor resolution, the CA
  flash→RAM populator — plus the exact Req-side EXI grammars / root-event numbering [?], the DIN-vs-ISO
  DC_EVSEStatus layout [?], the exact EVSEIsolationStatus→level 3/4 mapping, and the CP/PP analog front-end
  acquisition (PP/CPD ADC channels + TIM4 CP input-capture on PD12). The EXI bit-grammar codec + the distributed
  session sequence/timers/retries + FAILED→shutdown (`analyze93`) + the transport carriage (`analyze94`) are
  **already recovered/built**; with the CP front-end stubbed unplugged the session holds idle and the EVSE
  inputs hold safe 0 (bench-injection via flag setters / `ccs2_rx_exi` exercises the downstream wiring). The
  confirmed measurement + actuation field maps are already wired.
- §5.5c — **asserted** power-stage drive (PB10/PB11 precharge, PD8 inner contactor, PC9 charge,
  PE7/PE8 d1/d2, PD3/PE4 e-lock) — **LAST**, behind a compile-time safety flag, drive **only** once
  the controller is bench-validated. **Actuation architecture (§5.21 F, `analyze90`):** the adapter has
  **no local PWM/DAC current actuation** — it is a protocol bridge + contactor controller. The current
  setpoint (`EVTargetCurrentValue`) is commanded to the upstream CCS2 EVSE via the DIN70121
  `CurrentDemandReq` PLC message (the EVSE regulates the DC output); the power path is switched by the
  contactor GPIO above; CHAdeMO H108/H109 report the EVSE output measurements back to the vehicle. So the
  asserted "drive" = contactor GPIO sequencing + the CCS2 `CurrentDemandReq` message, not a PWM/DAC register.