# custom_fw — safe-bootstrap + CAN1 message layer + HV measurement + inert charge stm + inert current control + CCS2 EVCC subsystem (vendored mbedTLS + lwIP) (Orientrise KM-CCS2CHAdeMO-1)

A **minimal, flashable, stock-reversible** custom application for the adapter
(STM32F427/F429, Cortex-M4), being built up in incremental, independently-testable layers
toward a safe CHAdeMO charge controller. It proves the full **build → wrap → flash → recover**
pipeline end-to-end on the byte-derived memory layout (REPORT §5.19) and boot entry contract
(§5.15/§5.16). **Current stage: SAFE BOOTSTRAP + CAN1 MESSAGE LAYER + HV MEASUREMENT + INERT CHARGE
STM + INERT CURRENT CONTROL + CCS2 EVCC SUBSYSTEM + CP/PP ANALOG FRONT-END + ND6 + PnC CA STORE** — clocks + timebase + GPIO safe-state + CAN1
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
mbedTLS transport carriage** (`analyze94`, `src/v2g_net.c`) are now **recovered and built**, as is the **CP/PP
analog front-end** (`analyze95`, `src/cp_capture.c` TIM4 CP PWM capture + `src/cp_adc.c` ADC3 PP/CPD/BAT —
measurement only), as is the **PnC CA cert store** (`analyze96`, `src/ca_store.c` — communication only). The
**network + crypto third-party stacks are now vendored, not hand-rolled**: the stock C013 stack IS **lwIP 2.1.x**
(IPv6/ND6/TCP/UDP) + **Mbed-TLS 2.28** (TLS 1.2 EVCC client), identified from the bytes (`analyze97`), so
`third_party/` vendors **mbedTLS 2.28.9 + lwIP 2.1.4** configured byte-faithfully to the recovered config
(`src/mbedtls_config.h` + `src/lwipopts.h`); the recovered glue (`v2g_net.c` transport SM / V2GTP deframe / EXI
dispatch / SDP / QCA7005 netif / `ca_store` populator / `hw_rng` f_rng) wires into the library APIs via
`src/v2g_stack.c`. The earlier hand-rolled crypto/ecc/x509/tcp/tls/nd6 replicas are **retired** (their mechanisms
remain documented in REPORT §5.9 + `analyze95/96/97` and are validated by `test_tls_mbedtls`). The asserted
power-stage drive (incl. the BCB PD11 drive + the +24 V power-fail queue) stays GATED until bench-validated.

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
  no GPIO**. The engagement guard only passes when `flag==1 && phase_status==4 && outvol ∈ [ress_vol−10,
  ress_vol+5] && dwell≥250`. **`ress_vol` is the EVSE PresentVoltage** (`din_scale(meas+0x3D18/1A)`,
  `ccs2_evse()->evse_present_voltage`), **NOT the H102 TargetBatteryVoltage** — proven byte-exact from C013
  `0x0804AADA–0x0804AAEE` (`udiv sl = scale(EVSEPresentVoltage)`) and the dual log `0x0804AB40` which prints
  `ress_vol` and `TargetBatteryVoltage` as separate values. During precharge the EVSE reports the *battery*
  voltage here (~364 V on a ZE1), not the full-charge target (410 V); using the target as the reference puts
  the window at [400,415], which the precharge output can never reach → state-17 stalls to timeout → 450
  (the C009 abort). The EVSE-side handshake inputs (phase_status/precharge_flag/plug_in/…) are
  **supplied by the CCS2 EVCC controller** (`ccs2_evse()`, §5.9) — `plug_in` now reflects the measured PP
  voltage (the real CP/PP front-end, `analyze95`), but the DIN-derived handshake inputs (precharge/
  cablecheck/…) hold 0 until a live EXI session, so the machine holds in the early states and **cannot
  engage**. Interlocks (whole-bus 1525-tick / per-message 100-tick CAN watchdogs, H102 fault,
  emergency, bms/hw fault, CurrentDemand isolation==3) force a safe stop state. Host-unit-tested
  (`test_charge_stm.c`, 55 checks incl. the ZE1 present-voltage-reference regression). State/interlock/engage/action are SWD-readable (`stm_*`).
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
- **Inert G11 EVMaximumCurrentLimit ramp**: `current_ramp_step` runs the C013 state-30 **periodic** current-limit
  ramp (§5.17 G11, `analyze105`, byte-exact `0x0804BB54–0x0804BBE8`) as a **shadow limit** — the slow inrush layer
  distinct from the per-tick `current_ctrl` min/cap law above. It ramps the **requested** `EVMaximumCurrentLimit`
  (stock `meas+0x28C`) up **+20 A/minute** tracking the EVSE present current (= `current_ctrl` avail), clamped to
  the EVSE max (= cap): init **20 A**, `phase_cnt%10` gate, **FINE** +20 A on `phase_cnt%6000==0` (6000 ticks =
  60 s = 1 min @100 Hz) within a **±5 A** deadband, **COARSE** +20 A/10 ticks within a **±25 A** deadband gated
  `p[+0x64]>=600`; 32-bit unsigned deadband math (the coarse +25 bound is `(setpoint−25)+50`, wrapping at the
  20 A init), ceiling clamp, and `EVMaximumCurrentLimit = min(ramped, ceiling)` (`0x0804EA94`). Both paths only
  **add** +20 A — **not** the prior-art +4 A/100 ms fast ramp. It **drives no power stage**. Wired in `main`
  CurrentDemand (re-init 20 A on state-30 entry; `phase_cnt` = the genuine `p[+0x4]` via `charge_stm_phase_cnt()`);
  with the EVSE measurements stubbed 0 the ceiling is 0, so it **never steps** and `max_limit` stays 0 — no limit
  asserted. Host-unit-tested (`test_current_ramp.c`, 38 checks). Ramped setpoint + advertised limit are
  SWD-readable (`cc_ramp_setpoint`/`cc_max_limit`) and surfaced into `meas+0x28C`.
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
  (UDP→SDP / TCP→deframe→`ccs2_rx_exi`), `ccs2_step` drives the transport SM + starts TCP at SDP-done. The live
  IPv6/ND6/TCP/UDP + TLS/crypto is owned by the **vendored lwIP 2.1.4 + mbedTLS 2.28.9** (`src/v2g_stack.c`,
  configured byte-faithfully to the recovered C013 config — `analyze97`); the **CP/PP analog front-end is now
  recovered/built** (`analyze95`, `src/cp_capture.c` TIM4 CP capture + `src/cp_adc.c` ADC3 PP/CPD/BAT), so
  `cp_step` is fed the real measured CP duty/period + PP/CPD raw + PD11/D_LINK (`plug_in` reflects the measured
  PP voltage); the DIN-derived EVSE handshake inputs still hold 0 until a live session, and the session-flag
  setters allow bench injection. In CurrentDemand the `CurrentDemandReq` image is produced
  (`ccs2_cd_req`/`ccs2_cd_req_len`) and sent via `v2g_net_tcp_send` — **inert**: it only transmits when the
  transport is ESTABLISHED (gated TCP connect/TLS handshake), so nothing is commanded in normal operation.
  Host-unit-tested (`test_{v2gtp,slac,cp,cp_capture,cp_adc,sdp,din70121,ccs2,exi,din_session,v2g_net,ca_store}.c`,
  14/54/32/42/42/31/74/23/85/42/90/45 checks; `test_tls_mbedtls` 21 validates the real-library TLS handshake;
  full host suite 760). `ccs2_st`/`ccs2_link`/`ccs2_secc`/`ccs2_proto` +
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

## Third-party libraries — mbedTLS 2.28.9 + lwIP 2.1.4 (the library pivot)

The stock C013 CCS2 network stack **is** open-source **lwIP 2.1.x** (IPv6/ND6/TCP/UDP) + **Mbed-TLS 2.28**
(TLS 1.2, EVCC client) — identified structurally from the bytes (`analyze97.py`: the `ssl_setup 0x080604D2`
call graph matches the mbedTLS client API; the analyze96 `nd6_input`/`ethernet_input`/`ip6_input` symbols are
lwIP; the recovered config constants map one-to-one onto the library option macros). Per the project preference
for established open-source libraries over from-scratch reimplementations, `third_party/` **vendors the real
libraries** rather than replicating them:

- `third_party/mbedtls/` — **Mbed-TLS 2.28.9** (library subset: AES/SHA256/MD5/ECP/ECDH/ECDSA/BIGNUM/ASN1/OID/
  PK/X509/SSL-TLS-client/cipher/md/memory_buffer_alloc).
- `third_party/lwip/` — **lwIP 2.1.4** (core IPv6/ND6/TCP/UDP/ICMP6 + `netif/ethernet`); `NO_SYS=1` raw API.

**Byte-faithful config** (recovered values → library macros; `analyze97.py` asserts the mapping, 63 checks):

- `src/mbedtls_config.h` — selected with `-DMBEDTLS_CONFIG_FILE='"mbedtls_config.h"'`. **CLIENT-only**
  (`SSL_CLI_C`, no `SSL_SRV_C` — the adapter is the EVCC), `SSL_PROTO_TLS1_2`, EtM (`SSL_ENCRYPT_THEN_MAC`,
  recovered config bit9) + EMS (`SSL_EXTENDED_MASTER_SECRET`, bit10), `IN=OUT=MAX_CONTENT_LEN 8192` (recovered
  `0x2000`), `KEY_EXCHANGE_ECDHE_ECDSA_ENABLED` (`0xC023`) + `ECDH_ECDSA_ENABLED` (`0xC025`),
  `ECP_DP_SECP256R1_ENABLED` **only**, `AES_C`+`AES_ROM_TABLES`+`CIPHER_MODE_CBC`+`CIPHER_PADDING_PKCS7`,
  `SHA256_C`(+224)+`MD5_C` (sig_hashes {6,5,3}, **no** SHA1/SHA512), `ECDH_C`+`ECDSA_C`+`BIGNUM_C`,
  `X509_CRT_PARSE_C`+`PK_PARSE_C`+`ASN1_PARSE_C` (**DER**, no PEM/base64), `MEMORY_BUFFER_ALLOC_C` (static-pool
  heap), `NO_PLATFORM_ENTROPY`+`NO_DEFAULT_ENTROPY_SOURCES` (RNG = STM32 HW-RNG `0x50060800`, **not** ctr_drbg),
  no RSA/GCM/FS/net/time/debug. Ends `#include "mbedtls/check_config.h"`.
- `src/lwipopts.h` — `NO_SYS 1` raw API, IPv6-only (`LWIP_IPV4 0`/`IPV6 1`), `TCP`+`UDP`+`ICMP6`,
  `ETHERNET 1`/`ARP 0`, `IPV6_FRAG`+`REASS 1` (V2GTP EXI frames up to 8509 B > MTU), `TCP_MSS 1460` /
  `TCP_WND 11680` / `TCP_SND_BUF 14600` (10·MSS) / `TCP_SND_QUEUELEN 40` / `SYNMAXRTX 3` / `MAXRTX 4` /
  `TMR_INTERVAL 250` / `MSL 60000`, ND6 `REACHABLE_TIME 30000` / `RETRANS_TIMER 1000` / `NUM_NEIGHBORS 8`,
  `SUPPORT_CUSTOM_PBUF 1`, static pools (`MEM_LIBC_MALLOC 0`), all checksums SW (QCA7005 has no offload),
  no stats/debug/asserts. `tcp_backoff`/`tcp_persist_backoff` use lwIP defaults (match the recovered tables).

**Freestanding build** (`-nostdlib`): a tiny libc shim (`src/libc_shim.c/.h`: memcpy/memset/memmove/strlen/
strcmp/strncmp/malloc-free-over-static-pool/errno) + `src/arch/cc.h` (lwIP compiler abstraction) satisfy the
libraries' libc references; mbedTLS heap = `MBEDTLS_MEMORY_BUFFER_ALLOC_C` over a static 64K CCM pool
(`mbedtls_heap[65536]` in `.ccm_bss`); lwIP `NO_SYS=1` raw API (no OS, RX ISR only queues frames). `build.sh`
compiles the lwIP subset + the mbedTLS `library/*.c` glob with the two config headers.

**Architecture — glue vs libraries.** The libraries own the live stack; the **recovered glue stays** and wires
into the library APIs:

- `src/v2g_stack.c/.h` — the live stack: lwIP `netif` (QCA7005 driver underneath) + raw TCP/UDP pcb +
  mbedTLS bio bridge (`tls_ciphers {0xC023,0xC025,0}`, `ssl_conf_authmode VERIFY_REQUIRED`,
  `x509_crt_parse` + `ssl_conf_ca_chain` from `ca_store`, `hw_rng` `f_rng`). Exposes
  `v2g_stack_init/connect_ip/tls_setup/tls_handshake/tcp_send/tls_write/udp_send/poll/tcp_close/local_ip` +
  recv/connected/closed callbacks.
- `src/v2g_net.c/.h` — recovered transport **glue**: pure wire helpers (EUI-64 link-local / mcast MAC /
  IPv6/UDP/TCP build-parse / Internet checksum / Ethernet framing — kept as byte-exact reference framing),
  V2GTP stream deframe, EXI dispatch → `ccs2_rx_exi`, **TLS decision (TLS iff SECC security byte==0)**,
  transport SM (connect 30000 ms / idle≥300 close / TLS handshake) calling `v2g_stack_*`.
- `src/ca_store.c` populator → `mbedtls_x509_crt_parse` + `ssl_conf_ca_chain`; `src/hw_rng.c` → `f_rng`;
  `src/qca7005.c` → lwIP netif linkoutput/input; `src/sdp.c` → `v2g_stack_udp_send`.

**Retired replicas.** The earlier hand-rolled `src/{crypto,ecc,x509,tcp,tls,nd6}.c/.h` + their host tests are
**removed** (superseded by the vendored libraries). Their mechanisms remain documented in REPORT §5.9 +
`analyze95/96/97` and are validated end-to-end by `test_tls_mbedtls` (real-library handshake). `src/nd6.c`'s
byte-exact ND6 mechanism now lives in lwIP `nd6` (the NS-receive DELAY/counter=5 C013 deviation is documented;
lwIP uses STALE=3 — a noted stock deviation).

**Host integration test** (no hardware — proves the recovered mbedTLS config end-to-end with the **real**
library: client/server memory-bio handshake):

```sh
nix-shell -p gcc --run 'gcc -O2 -w -D_GNU_SOURCE -I. -Isrc -Ithird_party/mbedtls/include \
  -DMBEDTLS_CONFIG_FILE='"'"'"test_mbedtls_config.h"'"'"' \
  -o test_tls_mbedtls test_tls_mbedtls.c third_party/mbedtls/library/*.c && ./test_tls_mbedtls'
```

Expected: `21 checks, 0 failures` — negotiates `0xC023` (ECDHE-ECDSA-AES128-CBC-SHA256), `VERIFY_REQUIRED`
enforced (empty-CA → `−0x2700` / verify_result `0x08` NOT_TRUSTED), `0xC025` alt negotiates, encrypted app-data
round-trip both directions. `test_mbedtls_config.h` is a **host-test-only** wrapper (`#include "mbedtls_config.h"`
then `#define MBEDTLS_SSL_SRV_C` for the harness server — the firmware config stays client-only).

**Still GATED:** the asserted power-stage drive (contactor/relay GPIO sequencing) stays the last gated layer
(§5.21/§7). The library network/crypto layers are present and inert-validated, not gated-to-implement.

## Files

| file | purpose |
|---|---|
| `linker.ld` | GNU ld script: FLASH `0x08020000` 640K (app sectors 5–9), RAM `0x20000000` 192K, CCM `0x10000000` 64K, `_estack=0x20030000` (§5.19) |
| `startup.s` | vector table + self-bootstrapping `Reset_Handler`: MSP from `vector[0]`, `VTOR=0x08020000`, copy `.data`, zero `.bss`+CCM, call `main`; weak core + CAN1 (IRQ19–22) + TIM4 (IRQ30) + DMA2_Stream0 (IRQ56) + DMA2_Stream1 (IRQ57) handler aliases (the boot writes no MSP/VTOR, §5.15/§5.16) |
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
| `test_charge_stm.c` | host unit test (gcc, no hardware): engagement-guard window/thresholds + unsigned wrap, sequence walk/stall/engagement, interlocks, C009-mismatch never-engages, ZE1 present-voltage-reference regression (ress_vol = EVSE PresentVoltage, not H102 target) — 55 checks |
| `src/current_ctrl.c/.h` | **inert** H102 output-current control law (shadow setpoint): state-30 `setpoint=min(request,EVSE avail)` capped by EVSE max, `target_v=min(target,limit)`, byte-exact `/1000` scale + converter `0x0804E786`=pow10 TABLE[code] (corrects analyze89; delegates to `din_pow10`/`din_scale`), zero-skip keep-previous; drives no power stage; EVSE measurements from `ccs2_fill_current_ctrl()` (§5.21 E, `analyze89`/`analyze92`) |
| `test_current_ctrl.c` | host unit test (gcc, no hardware): pow10 converter/scale, min/cap law, target-voltage limit, zero-skip, EVSE-stub safety (setpoint held 0) — 46 checks |
| `src/current_ramp.c/.h` | **inert** G11 periodic EVMaximumCurrentLimit ramp (shadow limit): byte-exact `0x0804BB54–0x0804BBE8` — init 20 A, `phase_cnt%10` gate, FINE +20 A/`%6000` (±5 A deadband) / COARSE +20 A/10 ticks (±25 A deadband, `p[+0x64]>=600`), 32-bit unsigned deadband math + ceiling clamp, `EVMaximumCurrentLimit=min(ramped,ceiling)`; target=EVSE present current (avail), ceiling=EVSE max (cap); drives no power stage; wired in `main` CurrentDemand, re-init 20 A on state-30 entry (§5.17 G11, `analyze105`) |
| `test_current_ramp.c` | host unit test (gcc, no hardware): 20 A init, `%10`/`%6000` gates, FINE ±5 + COARSE ±25 deadbands, `p64>=600` gate, unsigned −25 wrap, ceiling clamp, `min(ramped,ceiling)`, EVSE-stub safety (no step, limit 0) — 38 checks |
| `src/qca7005.c/.h` | QCA7005 PLC SPI1 host driver + MME/Ethernet transport: `CR1=0x0357` (Mode 3/master//8/8bit/MSB/SSM), CS=PA4, reset=PC5, IRQ=PC4 polled; reg read `0xC000\|addr` / write `0x4000\|addr`; reg-init (sig `0xAA55` + `0x1200=0xC5B`/`0xC00=0x447`/`0xD00=0x41`); `0xAA`/`0x55`-framed buffer TX/RX; MAC-read MME `0xA000`/`0xA001`; 4096 B RX ring + per-frame callback; communication only, no power GPIO (§5.9, `analyze91`) |
| `test_qca7005.c` | host unit test (gcc, no hardware): MAC-read REQ build, MAC-read CNF validation, RX packet-header parse math — 26 checks |
| `src/v2gtp.c/.h` | V2GTP framing: encode/parse `01 FE type BE len BE`; types `0x8001` EXI / `0x9000` SDP-req / `0x9001` SDP-res (§5.9, `analyze92`) |
| `src/slac.c/.h` | ISO15118-3 SLAC matching SM + MME builders/validators (PARM/ATTEN/SOUND/MATCH/SET_KEY) + PRNG LCG → NID/NMK/EVSE-MAC/link-up; communication only (§5.9, `analyze92`) |
| `src/cp.c/.h` | CP/PP analog signaling: scaling getters (`AD_PP`/`AD_CPD`/`AD_BAT`), CP-state char, duty-5 detector, PP plug-in hysteresis+4-debounce; BCB recorded only (gated); fed the real CP/PP front-end (`cp_capture`+`cp_adc`, `analyze95`); labeling corrected `cp_ad_cp`→`cp_ad_bat`, `cp_freq`→period µs (§5.9, `analyze92`/`analyze95`) |
| `src/cp_capture.c/.h` | **CP PWM TIM4 input-capture front-end** (`analyze95` J, measurement only): PD12 AF2 TIM4_CH1, `TIM4_IRQHandler` (IRQ30); duty per-mille 1000×CCR2/CCR1 + period µs (NOT Hz), validity CCR1∈[950,1050] + median-of-9 span≤15 + DC deglitch (0 needs 128 / 1000 needs 32); pure `cp_capture_median`/`process` + init/ISR wrapper (§5.9) |
| `test_cp_capture.c` | host unit test (gcc, no hardware): median extraction/sort, publish-deglitch, ISR-body validity gate + duty/period math — 42 checks |
| `src/cp_adc.c/.h` | **PP/CPD/BAT ADC3 analog front-end** (`analyze95` I, measurement only): ADC3 ch2=PA2 PP / ch0=PA0 CPD / ch12=PC2 BAT off the shared TIM8 125 kHz TRGO, DMA2 Stream1 circular `DMA2_Stream1_IRQHandler` (IRQ57); pure `cp_adc_publish` accumulates accA+=2×ch2 / accB+=ch12 / accC+=ch0, publishes every 8 TC (1.024 ms) — **PP=16·Σch2 (PA2 ONLY; 4·ch1 is a separate +24 V byproduct, NOT PP — CORRECTED)**; pure ×3300/65520 / ×6600/32760 / ×3300/32760 mV scaling; D_LINK PB12 / PD11 read-only IDR reads (BCB drive gated) (§5.9) |
| `test_cp_adc.c` | host unit test (gcc, no hardware): single-event accumulate/no-publish, PP-excludes-ch1, 8-event publish+clear, full-scale, scaling truncation, per-event weighting — 42 checks |
| `src/sdp.c/.h` | SECC Discovery SM + security select (low-byte cert-count test) + SDP req/res build/validate/parse + appHandshake protocol select (DIN/ISO); **TLS wire labels corrected** (`SDP_SECURITY_TLS=0x00`/`NONE=0x10`, `use_tls=(secc_security==0)`); UDP send via `v2g_net_udp_send` (§5.9, `analyze92`/`analyze94`) |
| `src/din70121.c/.h` | DIN70121 measurement struct + pow10 converter/scale (`0x0804E786` correction) + CurrentDemandRes decode + EV-target setter (arm 0x606) + CurrentDemandReq encode + **EXI grammar messages** (CurrentDemandRes complete 10-field / CableCheck / PreCharge / SessionStop decode + CurrentDemandReq grammar encode) (§5.9, `analyze92`/`analyze93`) |
| `src/exi.c/.h` | **EXI bit-level codec** (`analyze93` E): byte-exact MSB-first readBits/writeBits + varlen u16/u32 + signed ones-complement + octet + PhysicalValueType wire order (Multiplier,Unit,Value) + V2GTP/0x80/7-bit-event framing; pure logic, no power GPIO (§5.9) |
| `src/din_session.c/.h` | **autonomous DIN session SM** (`analyze93` F, inert): state enum 0..13 + timers 4000/120000/150000/40000/14000 ms (global vs engagement-phase) + retry cap 20 + CD modulo cadence + FAILED→shutdown + fault post (records code, drives no GPIO); Req images via a TX hook → `v2g_net_tcp_send` (§5.9) |
| `src/ccs2.c/.h` | CCS2 EVCC controller glue: RX EtherType dispatch (MME→SLAC, **IPv6→`v2g_net_rx_ethernet`**) + session sequencing driving `din_session_step` + transport SM (`v2g_net_step`/`start_tcp`) + `ccs2_evse()` handshake outputs (sourced from the session SM while active) + `ccs2_fill_current_ctrl()` EVSE measurements + `ccs2_demand()` CurrentDemandReq actuation image + `ccs2_rx_exi()` decoded-Res entry (fed by the live transport) + session-flag setters (bench injection); communication only, no power GPIO (§5.9, `analyze92`/`analyze93`/`analyze94`) |
| `src/v2g_net.c/.h` | **transport glue** (`analyze94` G/H + library pivot, inert): pure wire helpers (EUI-64 link-local from PIB MAC + mcast MAC, IPv6/UDP/TCP header build/parse, Internet + pseudo-header checksum, Ethernet framing — byte-exact reference framing), V2GTP stream deframe, **TLS decision (TLS iff SECC security byte==0; wire 0x00=TLS/0x10=No-TLS)**, transport SM (connect 30000ms / idle≥300 close / TLS handshake) calling `v2g_stack_*`, RX demux→SDP/EXI dispatch→`ccs2_rx_exi`, TX UDP/TCP/TLS send router, 16×128B diagnostic trace ring; the live IPv6/ND6/TCP/UDP + TLS/crypto is owned by the **vendored lwIP + mbedTLS** (`v2g_stack`); no power GPIO (§5.9) |
| `test_v2g_net.c` | host unit test (gcc, no hardware; `ccs2_rx_exi`/`sdp_rx` spied + `v2g_stack_*` stubbed): EUI-64/mcast MAC, IPv6/UDP/TCP build/parse, Internet checksum vector, TLS decision, V2GTP deframe (single/multi/partial/byte-by-byte), transport SM (plain/TLS/idle/timeout) via stack spies, EXI dispatch, RX UDP/TCP demux, TX send router (udp/tcp/plain-tcp/TLS-tls_write/before-established) — 90 checks |
| `src/v2g_stack.c/.h` | **live network/crypto stack** (library pivot): lwIP `netif` (QCA7005 driver underneath) + raw TCP/UDP pcb + mbedTLS bio bridge; `tls_ciphers {0xC023,0xC025,0}` + `ssl_conf_authmode VERIFY_REQUIRED` + `x509_crt_parse`/`ssl_conf_ca_chain` from `ca_store` + `hw_rng` `f_rng`; `mbedtls_heap[65536]` in `.ccm_bss`; exposes init/connect_ip/tls_setup/tls_handshake/tcp_send/tls_write/udp_send/poll/tcp_close/local_ip + recv/connected/closed callbacks (§5.9, `analyze97`) |
| `src/mbedtls_config.h` | **vendored mbedTLS 2.28.9 config** (byte-faithful to recovered C013): CLIENT-only TLS1.2 + EtM/EMS + 8192 content + ECDHE_ECDSA(0xC023)/ECDH_ECDSA(0xC025) + secp256r1-only + AES-CBC/PKCS7/ROM + SHA256/MD5 (no SHA1/512) + X509 DER (no PEM) + MEMORY_BUFFER_ALLOC_C + NO_PLATFORM_ENTROPY/NO_DEFAULT_ENTROPY_SOURCES (HW-RNG) + no RSA/GCM; selected `-DMBEDTLS_CONFIG_FILE='"mbedtls_config.h"'` (§5.9, `analyze97`) |
| `src/lwipopts.h` | **vendored lwIP 2.1.4 config** (byte-faithful to recovered C013): NO_SYS 1 raw API / IPv6-only / TCP+UDP+ICMP6 / ETHERNET 1 ARP 0 / frag+reass / MSS1460 WND11680 SND_BUF14600 QUEUELEN40 SYNMAXRTX3 MAXRTX4 TMR250 MSL60000 / ND6 30000/1000/8 / SUPPORT_CUSTOM_PBUF 1 / static pools MEM_LIBC_MALLOC 0 / SW checksums / no stats/debug (§5.9, `analyze97`) |
| `src/libc_shim.c/.h` + `src/arch/cc.h` | freestanding `-nostdlib` support: tiny libc shim (memcpy/memset/memmove/strlen/strcmp/strncmp/malloc-free-over-static-pool/errno) + lwIP compiler abstraction (`arch/cc.h`) satisfying the vendored libraries' libc references |
| `src/hw_rng.c/.h` | STM32 HW-RNG (`0x50060800`) driver + `hw_rng_f_rng` callback wired as the mbedTLS `f_rng` (stock RNG is HW-RNG, **not** ctr_drbg); `hw_rng_init` + `v2g_stack_set_rng` (§5.9, `analyze97`) |
| `third_party/mbedtls/` + `third_party/lwip/` | **vendored Mbed-TLS 2.28.9 + lwIP 2.1.4** (the real open-source libraries, configured by the two headers above); `third_party/README.md` records provenance + the library subset built |
| `test_tls_mbedtls.c` + `test_mbedtls_config.h` | host integration test (gcc, no hardware; **real** mbedTLS client/server memory-bio handshake): negotiates 0xC023, VERIFY_REQUIRED enforced (empty-CA→−0x2700/0x08), 0xC025 alt, encrypted app-data round-trip — 21 checks; `test_mbedtls_config.h` = host-only wrapper (`#include "mbedtls_config.h"` + `MBEDTLS_SSL_SRV_C` for the harness server; firmware config stays client-only) |
| `src/ca_store.c/.h` | **PnC CA cert store** (`analyze96`, communication only): ext-SPI master hdr@`0x1F8000` (magic `0xCEA155E1`/version1/size/byte-sum) validate + data@`0x1F8010` read via `spi4_read` → compact NULL-term Root(0x8101) ptr-array of {der_len,DER} entry+4 pointers (808 B entries, der_len≤800); `ca_store_root_count` feeds the SDP No-TLS gate; ext-SPI→RAM directly (no internal A/B management), no power GPIO (§5.9) |
| `test_ca_store.c` | host unit test (gcc, no hardware; `spi4_read` stubbed, RAM flash image): header validate, byte-sum, entry/contract validators, compact ptr-array populate (slots 0/2/4→3 roots, NULL-term, {len,DER} deref), `ca_store_init` (hdr+cksum+populate, root_count gate, bad-cksum/magic/version rejected) — 45 checks |
| `test_v2gtp.c` / `test_slac.c` / `test_cp.c` / `test_sdp.c` / `test_din70121.c` / `test_ccs2.c` / `test_exi.c` / `test_din_session.c` | host unit tests (gcc, no hardware; QCA7005 stubbed where needed): V2GTP framing 14, SLAC sequence walk 54, CP/PP scaling/state/plug 32, SDP security/req/res/protocol 31, DIN pow10/CD-res/CD-req/DC_EVSEStatus-grammar + B2 DIN-document codec round-trips 74, CCS2 integration 23, EXI primitives/PVT/framing + DIN-doc framing 85, session sequence/timers/retry/cadence/faults 42 checks (full host suite **760** with `test_v2g_net` 90 + `test_ca_store` 45 + `test_cp_capture` 42 + `test_cp_adc` 42 + `test_charge_stm` 55 + `test_current_ctrl` 46 + `test_current_ramp` 38 + `test_qca7005` 26 + `test_tls_mbedtls` 21) |
| `main.c` | rcc→gpio_safe→hv→ca_store_init→cp_capture_init→cp_adc_init→can→chademo→charge_stm→current_ctrl→tick→`cpsie i`→qca7005_init→hw_rng_init→`v2g_stack_set_rng(hw_rng_f_rng)`→ccs2_init→`v2g_net_set_local_mac` [EUI-64 from PIB MAC], then 100 Hz loop (feed IWDG + `heartbeat` + publish `hv_*` + RX parse + cp_step [real CP/PP front-end: cp_capture duty/period + cp_adc PP/CPD raw + PD11/D_LINK; publish `cp_cap_*`/`cp_plug`/`cp_state`/`cp_pp_mv`/`cp_cpd_mv`/`cp_bat_mv`/`cp_pp_raw`/`cp_cpd_raw`/`cp_d_link`/`cp_pd11`] + ccs2_step [drives din_session_step + v2g_net_step] + `charge_stm_step` with EVSE inputs from `ccs2_evse()` [publish `stm_*`] + `current_ctrl_step` in state-30 from `ccs2_fill_current_ctrl()` [publish `cc_*`] + `ccs2_demand` inert CD-req image + `v2g_net_tcp_send` [inert, only when ESTABLISHED; publish `ccs2_cd_req*`] + periodic TX + can_service + `qca7005_service`→ccs2_rx [publish `ccs2_*`] + `din_session_get` [publish `din_st_*`] + `v2g_net_get` [publish `v2g_net_st/mode/rx/tx`] + `v2g_stack_poll` [lwIP nd6_tmr + TCP timers driven inside v2g_net_step] + `ca_store_get/root_count` [publish `ca_root_count/ca_store_present`]); no asserted power drive |
| `build.sh` | builds via `nix-shell -p gcc-arm-embedded python3` → `app.elf`/`app.bin`, verifies vectors, pads to sector 5 |
| `verify_pad.py` | checks `vector[0]==0x20030000`, `vector[1]` is an in-app Thumb address; pads `app.bin` → `app_padded.bin` (128 KB, `0xFF` tail) |
| `verify_ccs2.py` | disasm-verifies the built CCS2/EXI/session/transport-glue/CP-front-end/lwIP-ND6/CA + `v2g_stack`/mbedTLS/`hw_rng` modules: presence of wired symbols (incl. `din_session_*` + `v2g_net_*`/`v2g_stack_*` + `cp_adc_*`/`cp_capture_*` + lwIP `nd6_*`/`ca_store_*` + `mbedtls_ssl_*`/`x509_crt_parse` + `hw_rng_*`), **power-GPIO safety** (no peripheral base `0x400xxxxx` referenced in the pure-logic modules), main integration calls (incl. `din_session_get`/`v2g_net_get`/`v2g_net_tcp_send`/`cp_adc_init`/`ca_store_init`/`hw_rng_init`/`v2g_stack_set_rng`), pow10 converter table + the five session timer constants + retry cap 20 + transport cipher list {0xC023,0xC025} + IPv6 EtherType/next-header demux + `v2g_stack_tls_setup` bl-targets (ssl_conf_authmode/conf_ciphersuites/x509_crt_parse/ssl_setup) + **cp_adc_init ADC3/DMA2 register-exact values + NVIC ISER1 + read-only D_LINK/PD11 IDR reads (no GPIOB/GPIOE drive) + ISR accumulate/publish + bat_mv scaling** + **lwIP ND6 reachable/retransmit 30000/1000 + ICMPv6 types 135/136/134 + NA flags 0x22/0x60 + bic#0x0F + hop 255; CA magic 0xCEA155E1 + entry 808/DER 800 + Root 0x8101 + ext addrs 0x1F8000/0x1F8010 + data 9792** (−O2-inlined helpers verified via constants/displacements; T2 LDR-literal pool reads 4-aligned); **B2 DIN-document framing** (root 0x4D compare in `ccs2_rx_exi` + subev bound 36 / gid 0x6d choice 2 in `exi_din_decode_doc_start` + the 9 Req encoders / 5 new Res decoders / `din_dc_ev_status_encode` / `din_session_set_evccid` wired symbols); reports bench-only APIs gc-eliminated from the autonomous image — 222 checks |

Build outputs (`app.elf`, `app.map`, `app.bin`, `app_padded.bin`) are git-ignored.

## Build

```sh
bash build.sh
```

Produces `app.bin` (vectors + code, linked at `0x08020000`) and `app_padded.bin` (128 KB =
sector 5, matching the ground-truth `app5.bin` dump). Expected vectors:
`MSP=0x20030000`, `reset=0x080201AD` (handler `0x080201AC`, Thumb bit set). The SysTick vector
(offset `0x3C`) must point to `tick.c`'s strong `SysTick_Handler`, the CAN1_RX0 vector
(IRQ20, offset `0x90`) to `can.c`'s strong `CAN1_RX0_IRQHandler`, the TIM4 vector (IRQ30, offset
`0xB8`) to `cp_capture.c`'s strong `TIM4_IRQHandler`, the DMA2_Stream0 vector (IRQ56, offset `0x120`)
to `adc.c`'s strong `DMA2_Stream0_IRQHandler`, and the DMA2_Stream1 vector (IRQ57, offset `0x124`) to
`cp_adc.c`'s strong `DMA2_Stream1_IRQHandler` (all override the weak aliases).
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
gcc -O2 -Wall -Wextra -Isrc -o test_cp_capture test_cp_capture.c src/cp_capture.c                && ./test_cp_capture
gcc -O2 -Wall -Wextra -Isrc -o test_cp_adc    test_cp_adc.c    src/cp_adc.c                      && ./test_cp_adc
gcc -O2 -Wall -Wextra -Isrc -o test_sdp       test_sdp.c       src/sdp.c src/v2gtp.c             && ./test_sdp
gcc -O2 -Wall -Wextra -Isrc -o test_din70121  test_din70121.c  src/din70121.c src/exi.c          && ./test_din70121
gcc -O2 -Wall -Wextra -Isrc -o test_exi       test_exi.c       src/exi.c                         && ./test_exi
gcc -O2 -Wall -Wextra -Isrc -o test_din_session test_din_session.c src/din_session.c src/din70121.c src/exi.c && ./test_din_session
gcc -O2 -Wall -Wextra -Isrc -o test_ccs2      test_ccs2.c      src/ccs2.c src/slac.c src/sdp.c src/cp.c src/din70121.c src/exi.c src/din_session.c src/v2gtp.c src/v2g_net.c src/ca_store.c && ./test_ccs2
gcc -O2 -Wall -Wextra -Isrc -o test_v2g_net   test_v2g_net.c   src/v2g_net.c src/v2gtp.c          && ./test_v2g_net
gcc -O2 -Wall -Wextra -Isrc -o test_ca_store  test_ca_store.c  src/ca_store.c                    && ./test_ca_store
'
```

Expected: `14 / 54 / 32 / 42 / 42 / 31 / 74 / 85 / 42 / 23 / 90 / 45 checks, 0 failures` respectively (this
block **574**; the full host suite is **760** with `test_charge_stm` 55 + `test_current_ctrl` 46 +
`test_current_ramp` 38 + `test_qca7005` 26 + `test_tls_mbedtls` 21).
`test_slac.c` and `test_ccs2.c` provide their own `qca7005_frame_send`/`qca7005_mac` stubs (do **not** link
`src/qca7005.c` into those — it collides with the stubs); `test_ccs2.c` also stubs `tick_get`. `test_din70121.c`/
`test_ccs2.c`/`test_current_ctrl.c` link `src/exi.c` (the din70121 grammar codec references the EXI primitives);
`test_ccs2.c` also links `src/din_session.c` + `src/v2g_net.c` (the autonomous session SM + transport glue wired
into `ccs2_step`/`ccs2_rx`) + `src/ca_store.c` (the real PnC CA populator; `test_ccs2.c` stubs `spi4_read` →
root_count 0) and provides 18 no-op `v2g_stack_*` stubs (the live stack is exercised separately by
`test_tls_mbedtls`). `test_v2g_net.c` spies `ccs2_rx_exi`/`sdp_rx` + **stubs `v2g_stack_*`** (records the glue→
stack wiring; does not link the heavy ccs2/sdp/din modules or the libraries), and `test_ca_store.c` stubs
`spi4_read` with a RAM flash image. The pure protocol/scaling/measurement/codec/session/glue/CA logic compiles
and runs on the host; the **vendored lwIP + mbedTLS** live stack is validated end-to-end by `test_tls_mbedtls`
(real-library handshake, above) and the SPI paths are disasm-verified separately. The retired hand-rolled
`nd6`/`tcp`/`tls`/`crypto`/`ecc`/`x509` replicas + their tests are removed (lwIP/mbedTLS own those layers now).

**Built-image disasm verification** (power-GPIO safety + presence + pow10 table + transport constants + CP/PP front-end + ND6/CA):

```sh
nix-shell -p gcc-arm-embedded python3 python3Packages.capstone --run 'python3 verify_ccs2.py'
```

Expected: `222 checks, 0 failures` — confirms the wired CCS2/EXI/session/transport-glue/CP-front-end/lwIP-ND6/CA
+ `v2g_stack`/mbedTLS/`hw_rng` symbols are linked, the pure-logic modules reference **no** peripheral base
`0x400xxxxx` (no power GPIO), `main` calls the integration functions (incl. `din_session_get`/`v2g_net_get`/
`v2g_net_tcp_send`/`v2g_net_set_local_mac`/`cp_adc_init`/`ca_store_init`/`hw_rng_init`/`v2g_stack_set_rng`),
the pow10 converter table is present, the five session timer constants
(4000/120000/150000/40000/14000) + retry cap 20 are compiled into `din_session`, the transport cipher list
{0xC023,0xC025} + IPv6 EtherType (0xDD86 LE) + next-header UDP 17/TCP 6 demux are compiled into `v2g_net`,
`cp_adc_init` writes the byte-exact ADC3/DMA2 register values (CR1 `0x800` DISCEN, CR2 `0x1E000301`, SMPR1/2,
SQR1/2/3, DMA CR `0x04002D10`, CCR `0x0002A006`, LIFCR `0xF40`, NDTR 16, ADC3_DR +0x4C) + NVIC ISER1, with
`cp_adc_d_link`/`pd11` **read-only** IDR reads (no GPIOB/GPIOE drive) and the ISR accumulate/publish + `bat_mv`
×6600/32760 scaling present, and the **lwIP ND6** reachable/retransmit 30000/1000 + ICMPv6
types 135/136/134 + NA flags 0x22/0x60 + `bic #0x0F` (& 0xF0) + hop 255 and **CA** magic
`0xCEA155E1` + entry 808 / DER 800 + Root 0x8101 + ext addrs `0x1F8000`/`0x1F8010` + data 9792 constants are
compiled in (the small helpers are −O2-inlined into their callers, verified via constants/displacements; T2
LDR-literal pool reads are 4-aligned). Bench-only APIs gc-eliminated from the autonomous image are reported
informationally (host-tested above); the live `v2g_net` RX path now reaches the EXI decode chain (`ccs2_rx_exi`/
`exi_decode_header`/`din_session_rx`/`v2gtp_parse`), so those are retained.

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
8. **Confirm the CCS2 EVCC subsystem is communication-only**: read `&ccs2_st` over SWD — with no live EVSE
   the session sits at `0` (IDLE) and never advances to SLAC/SDP/session; `&ccs2_link`/`&ccs2_secc` stay `0`
   (`plug_in` now reflects the measured PP voltage, but the DIN-derived handshake inputs hold 0). The pure-logic
   modules (slac/cp/sdp/din70121/exi/din_session/ccs2/v2gtp) reference **no peripheral base** (disasm-verified,
   `verify_ccs2.py`) — they drive no power pin. In CurrentDemand the `CurrentDemandReq` EXI image is produced
   (`&ccs2_cd_req_len=108`, `&ccs2_cd_req[0..107]`) and sent via `v2g_net_tcp_send` — **inert**: it only
   transmits when the transport is ESTABLISHED (gated TCP connect/TLS handshake), so nothing is commanded to the
   EVSE in normal operation. The EXI grammar + autonomous session sequence/timers (`analyze93`;
   `&din_st_state`/`&din_st_fault`) **and the live transport carriage** (`analyze94`;
   `&v2g_net_st`/`&v2g_net_mode`/`&v2g_net_rx`/`&v2g_net_tx`) are recovered/built; the live IPv6/ND6/TCP/UDP +
   TLS/crypto is the **vendored lwIP + mbedTLS** (`v2g_stack`, `analyze97`), so with no live EVSE the session
   holds idle and the session-flag setters allow bench injection for testing the downstream
   charge-stm/current-control wiring. **No contactor should
   click and no HV should appear** — the CCS2 subsystem is communication only.
9. **Confirm the CP/PP analog front-end is measurement-only**: read `&cp_cap_duty` (CP duty per-mille,
   percent×10) / `&cp_cap_period` (CP PWM period µs; f_Hz = 1e6/period) / `&cp_cap_upd` (capture update counter)
   over SWD — with a 1 kHz CP PWM applied to PD12 these track the signal; with no signal `cp_cap_duty` holds its
   deglitched value. `&cp_pp_mv`/`&cp_cpd_mv`/`&cp_bat_mv` are the scaled ADC3 readings (PP=PA2/ch2 ×3300/65520,
   CPD=PA0/ch0 ×3300/32760, BAT=PC2/ch12 ×6600/32760), `&cp_pp_raw`/`&cp_cpd_raw` the published raw accumulators
   (PP=16·Σch2 — PA2 ONLY), `&cp_plug`/`&cp_state` the plug-in presence + CP state char, and `&cp_d_link` (PB12)
   / `&cp_pd11` (PD11 read-back) the digital reads. The front-end (`cp_capture` TIM4 IRQ30 + `cp_adc` ADC3/DMA2
   Stream1 IRQ57, `analyze95`) samples analog inputs + reads IDR — it drives **no power pin** (the BCB PD11
   drive + the +24 V power-fail queue stay gated; disasm-verified read-only, `verify_ccs2.py`). **No contactor
   should click and no HV should appear** — the CP/PP front-end is measurement only.

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

**Done (safe bootstrap + CAN1 message layer + HV measurement + inert charge stm + inert current control + CCS2 EVCC subsystem [QCA7005 transport + SLAC + CP/PP + SDP/V2GTP + DIN70121 + EXI codec + autonomous session SM + live transport] + CP/PP analog front-end):**
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
  **no GPIO**; EVSE-side handshake inputs now from `ccs2_evse()` (`plug_in` from the measured PP voltage;
  DIN-derived inputs hold 0 until a live EXI session). Host-unit-tested (`test_charge_stm.c`, 47 checks). **No power drive.**
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
  `din_st_*`). **Communication only, no power GPIO** (disasm-verified `verify_ccs2.py`, 171 checks). Host-unit-
  tested (`test_exi.c` 55, `test_din_session.c` 39; full suite 702). The live transport that feeds `ccs2_rx_exi`
  was subsequently recovered by `analyze94`, the CP/PP analog front-end by `analyze95`, and ND6 + the PnC CA
  cert store by `analyze96` (next bullets).
  **Still GATED:** exact Req-side grammars / root-event numbering [?], DIN-vs-ISO DC_EVSEStatus layout [?].
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
  (`test_v2g_net.c` 91; full suite 702). **GATED (third-party stacks, represented by hooks):** lwIP TCP
  reliability (SYN/ACK/retransmit/congestion), mbedTLS crypto (ECDHE/AES/SHA256/X509) + the TLS handshake/record
  SM. ND6 neighbor resolution + the CA flash→RAM populator were subsequently recovered by `analyze96` (next bullet).
- §5.9 CP/PP front-end addendum — **CP/PP analog acquisition** (`src/{cp_capture,cp_adc}.c`, via `analyze95`):
  the two independent measurement paths beneath the `cp.c` scaling/state/plug logic. `cp_capture` (TIM4_CH1
  PD12 AF2 PWM input-capture, IRQ30 — duty per-mille 1000×CCR2/CCR1 + period µs [NOT Hz], validity
  CCR1∈[950,1050] + median-of-9 span≤15 + DC deglitch [0 needs 128 / 1000 needs 32]), `cp_adc` (ADC3 ch2=PA2 PP
  / ch0=PA0 CPD / ch12=PC2 BAT off the shared TIM8 125 kHz TRGO, DMA2 Stream1 circular IRQ57, accumulate/publish
  every 8 TC=1.024 ms — **PP=16·Σch2 [PA2 ONLY; the 4·ch1 PA1 sum is a separate +0xC +24 V byproduct, NOT PP —
  CORRECTED]** + ×3300/65520 / ×6600/32760 / ×3300/32760 mV scaling + D_LINK PB12 / PD11 read-only IDR reads).
  `cp.c`/`cp.h` labeling corrected (`cp_ad_cp`→`cp_ad_bat`, `cp_freq`→period µs). Wired into `main`
  (`cp_capture_init` + `cp_adc_init` after HV; `cp_step` fed the real duty/period + PP/CPD raw + PD11/D_LINK;
  publish `cp_cap_*`/`cp_plug`/`cp_state`/`cp_pp_mv`/`cp_cpd_mv`/`cp_bat_mv`/`cp_pp_raw`/`cp_cpd_raw`/
  `cp_d_link`/`cp_pd11`). **Measurement only, no power GPIO** (the BCB PD11 drive + the +24 V power-fail queue
  stay gated; disasm-verified `verify_ccs2.py`, 171 checks). Host-unit-tested (`test_cp_capture.c` 42,
  `test_cp_adc.c` 42, `test_cp.c` 32; full suite 702).
- §5.9 ND6/CA addendum — **IPv6 ND6 neighbor discovery + PnC CA cert store** (`src/{nd6,ca_store}.c`, via
  `analyze96`): two of the four gated third-party hooks beneath the live transport. `nd6` (10×40 B neighbor cache
  + NS/NA/RA wire build/parse + 1 s `nd6_tmr` state countdown — NA-receive REACHABLE + Override-gated TLLA MAC;
  NS-receive DELAY/counter 5 [C013 deviation from stock STALE]; RA timers + is_router; solicited-node mcast
  `ff02::1:ffXX:XXXX`; `nd6_lookup` TX dst MAC defers until resolved), `ca_store` (ext-SPI master hdr@`0x1F8000`
  magic `0xCEA155E1`/version1/size/byte-sum validate + data@`0x1F8010` → compact NULL-term Root(0x8101) ptr-array
  of {der_len,DER} entry+4 pointers, 808 B entries der_len≤800; `ca_store_root_count` feeds the SDP No-TLS gate;
  ext-SPI→RAM directly, no internal A/B management). **CORRECTION:** the prior CA anchors `0x08050E14`/`0x08050B94`/
  `0x08051074`/`0x0804EB5C` were garbled — the real cluster is `0x080515CC`/`0x0805184C`/`0x08051500`/`0x0805159C`/
  `0x08051526`/`0x0804F58E`/`0x08051AAC`. Wired into `v2g_net` (nd6_init/set_send/set_local + ICMPv6 RX→nd6_input
  + tcp_send dst MAC via nd6_lookup), `ccs2` (sdp_init(ca_store_root_count())), `main` (ca_store_init after HV +
  nd6_tmr every 100 ticks + publish `nd6_*`/`ca_*`). **Communication only, no power GPIO** (disasm-verified
  `verify_ccs2.py`). Host-unit-tested (`test_ca_store.c` 45). The hand-rolled `nd6` replica was subsequently
  **retired** in favor of vendored lwIP `nd6` (next bullet); the CA populator stays as recovered glue.
- §5.9 library-identification addendum — **vendored mbedTLS 2.28.9 + lwIP 2.1.4 (the library pivot)**
  (`third_party/` + `src/v2g_stack.c` + `src/{mbedtls_config.h,lwipopts.h,libc_shim.c,hw_rng.c}` + `src/arch/cc.h`,
  via `analyze97`): the stock C013 stack IS lwIP 2.1.x + Mbed-TLS 2.28 client-only — identified from the
  `ssl_setup 0x080604D2` API call graph (ssl_init/config_init/x509_crt_init/x509_crt_parse≤5/conf_ca_chain/
  conf_authmode/conf_rng) + ciphersuite `int[]` @`0x080B0668` {0xC023,0xC025,0} + authmode arg1==0→VERIFY_REQUIRED
  mapping + the analyze96 lwIP ND6 symbols. So the **real open-source libraries are vendored** (per the project
  preference for established libraries over from-scratch replicas) and configured **byte-faithfully** to the
  recovered config: `mbedtls_config.h` (CLIENT-only TLS1.2 / EtM+EMS / 8192 content / ECDHE_ECDSA+ECDH_ECDSA /
  secp256r1-only / AES-CBC+PKCS7+ROM / SHA256+MD5 no SHA1/512 / X509 DER no PEM / MEMORY_BUFFER_ALLOC_C / HW-RNG
  no entropy/DRBG / no RSA/GCM) + `lwipopts.h` (NO_SYS 1 IPv6-only TCP/UDP/ICMP6 / frag+reass / MSS1460 WND11680
  SND_BUF14600 QUEUELEN40 SYNMAXRTX3 MAXRTX4 TMR250 MSL60000 / ND6 30000/1000/8 / custom-pbuf / static pools).
  Freestanding `-nostdlib` via a tiny libc shim + `arch/cc.h`; mbedTLS heap = static 64K CCM pool. The recovered
  **glue stays** (`v2g_net` transport SM/deframe/EXI-dispatch/TLS-decision, `sdp`, `qca7005` netif, `ca_store`→
  `x509_crt_parse`/`ssl_conf_ca_chain`, `hw_rng` f_rng) wiring into the library APIs via `v2g_stack` (lwIP netif +
  raw pcb + mbedTLS bio bridge). The hand-rolled crypto/ecc/x509/tcp/tls/nd6 replicas + their tests are **retired**
  (mechanisms remain documented in REPORT §5.9 + analyze95/96/97). `analyze97.py` **63 checks** (cipher list +
  ssl_setup API + authmode + recovered→vendored config mapping); host `test_tls_mbedtls` **21** proves the recovered
  config end-to-end with the real library (negotiates 0xC023, VERIFY_REQUIRED enforced empty-CA→−0x2700/0x08,
  0xC025 alt, encrypted app-data round-trip); full host suite **714/0** across 16 tests; `verify_ccs2.py` **222**;
  `CUSTOM.UPG` re-wrapped (132102 B, CRC residue 0 + app-verbatim + stock round-trip). **Communication only, no
  power GPIO** — the library network/crypto layers are now present + inert-validated, not gated-to-implement.

**Remaining layers:**
- CCS2 **remaining grammar gaps + bench validation**: the live UDP/TCP/IPv6 + mbedTLS
  transport **glue + wire framing + protocol decisions are recovered/built** (`analyze94`, `src/v2g_net.c`);
  the heavy third-party stacks are now **vendored** (lwIP 2.1.4 IPv6/ND6/TCP/UDP + mbedTLS 2.28.9
  ECDHE/AES/SHA256/X509 + the TLS handshake/record SM, configured byte-faithfully — `analyze97`,
  `src/v2g_stack.c`); the **DIN document model is now built** (`analyze101/102/103`, B2): every Req/Res
  rides the SINGLE root `0x4D` + DIN header (SessionID gid `0x6c` + gid `0x6d` choice 2) + a 6-bit message
  choice/subev — the old per-message "root events" were production grammar-ids misused as roots (removed).
  All **9 Req encoders** (SessionSetup/ServiceDiscovery/CPD/CableCheck/PreCharge/PowerDelivery/CurrentDemand/
  Welding/SessionStop) + **9 Res decoders** are wired through `din_session` TX/RX dispatch and `ccs2_rx_exi`
  strips the framing; the DC_EVStatus encoder is byte-exact (23-bit default grammar → `0x28 0x02 0x30`), the
  DC_EVSEStatus layout is the **merged grammar** (no DIN/ISO flag, `analyze103`), and the CPD Res DC-param
  limits feed `meas`. What remains [? partial]: the exact Req-side inter-field gate sequences (round-trip
  validated, not all stock gates pinned), the ServiceDiscovery list sub-grammars, per-builder SessionID
  negotiation, the exact EVSEIsolationStatus→level 3/4 mapping, and bench validation of the live session.
  The EXI bit-grammar codec + the distributed session
  sequence/timers/retries + FAILED→shutdown (`analyze93`) + the transport carriage (`analyze94`) + the CP/PP
  analog front-end acquisition (`analyze95`, PP/CPD/BAT ADC3 + TIM4 CP input-capture on PD12) + **the PnC CA
  flash→RAM populator** (`analyze96`, `src/ca_store.c`; ND6 neighbor resolution is now lwIP `nd6`) are **already
  recovered/built**; with no live EVSE the session holds idle and the DIN-derived EVSE
  inputs hold safe 0 (`plug_in` reflects the measured PP; bench-injection via flag setters / `ccs2_rx_exi`
  exercises the downstream wiring). The confirmed measurement + actuation field maps are already wired.
- §5.5c — **asserted** power-stage drive (PB10/PB11 precharge, PD8 inner contactor, PC9 charge,
  PE7/PE8 d1/d2, PD3/PE4 e-lock) — **LAST**, behind a compile-time safety flag, drive **only** once
  the controller is bench-validated. **Actuation architecture (§5.21 F, `analyze90`):** the adapter has
  **no local PWM/DAC current actuation** — it is a protocol bridge + contactor controller. The current
  setpoint (`EVTargetCurrentValue`) is commanded to the upstream CCS2 EVSE via the DIN70121
  `CurrentDemandReq` PLC message (the EVSE regulates the DC output); the power path is switched by the
  contactor GPIO above; CHAdeMO H108/H109 report the EVSE output measurements back to the vehicle. So the
  asserted "drive" = contactor GPIO sequencing + the CCS2 `CurrentDemandReq` message, not a PWM/DAC register.