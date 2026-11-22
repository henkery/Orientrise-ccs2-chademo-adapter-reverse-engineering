# CCS2 EVCC subsystem — completeness audit / gap inventory

Read-only audit of the `custom_fw` CCS2 (ISO 15118 / DIN 70121 **EVCC**) subsystem: what is **built and
host-tested**, what is **`[?]` not recovered**, and what is **GATED**. Purpose: scope the next build step
toward a *complete* CCS2 system. Every claim below is grounded in the current source (file:line) or the
byte-exact C013 decoders (`analyze91`–`analyze100`, REPORT §5.9). No firmware code is changed by this audit.

**Bottom line.** The CCS2 stack is **structurally complete** end-to-end — PLC transport → SLAC → CP/PP →
SDP/V2GTP → EXI bit-codec → DIN session SM → live lwIP/mbedTLS carriage → PnC CA store → controller glue —
all **inert / communication-only** (no power-stage GPIO; disasm-verified `verify_ccs2.py`). The critical-path
EXI application-message codec is **RE-covered AND integrated**: G1–G5 recovered byte-exact by `analyze101.py`
(Req encoder, 157 checks), `analyze102.py` (Res field lists, 170 checks), `analyze103.py` (DC_EVSEStatus +
isolation/phase mapping, 167 checks), then **built into the firmware** (B2, commit `017577d`): single root
`0x4D` framing + 9 Req encoders + 9 Res decoders + the three-signal split + session/ccs2 dispatch migration.
A further correctness fix (`analyze104.py`, commit `c8fc16a`) corrected the **state-17 engagement reference**:
`ress_vol` is the **EVSE PresentVoltage** (`meas+0x3D18/1A` scaled), NOT the H102 TargetBatteryVoltage — the
old target reference made the engagement window unreachable during precharge (the C009 abort). **What remains:**
(i) minor codec **fidelity partials** (G6–G8 + the B2 `[?]` gate-sequence / list-sub-grammar / optional-choice /
unit-enum / SID-negotiation items, §2); (ii) **charge-coordination** functional gaps surfaced by the prior-art
comparison (G10 PreCharge↔car-contactor coupling, G11 current ramp, §2); (iii) the bench-only **G9** live SECC
interop capture; and (iv) the **GATED-LAST** asserted power-stage drive (§4). The library network/crypto layers
are **done** (vendored, byte-faithful config). Full host suite **722 / 0**; `verify_ccs2.py` **222 / 0**.

---

## 1. Built layers (inert, host-tested, disasm-verified)

| Layer | Module(s) | Host test | Status |
|---|---|---|---|
| QCA7005 PLC SPI1 transport + MME/Ethernet | `qca7005.c` | `test_qca7005` 26 | built (`analyze91`) |
| SLAC ISO15118-3 matching SM (NID/NMK/MAC/link) | `slac.c` | `test_slac` 54 | built (`analyze92`) |
| CP/PP signaling + scaling/state/plug-in | `cp.c` | `test_cp` 32 | built (`analyze92`) |
| CP PWM TIM4 input-capture front-end | `cp_capture.c` | `test_cp_capture` 42 | built (`analyze95` J) |
| PP/CPD/BAT ADC3 analog front-end | `cp_adc.c` | `test_cp_adc` 42 | built (`analyze95` I) |
| SDP discovery + security/protocol select | `sdp.c` | `test_sdp` 31 | built (`analyze92`/`94`) |
| V2GTP framing (`01 FE type len`) | `v2gtp.c` | `test_v2gtp` 14 | built (`analyze92`) |
| EXI bit-level codec (MSB-first/varlen/signed/PVT) + DIN-doc framing | `exi.c` | `test_exi` 85 | built (`analyze93` E / B2) |
| DIN70121 meas + pow10 scale + B2 message codec (9 Req / 9 Res) | `din70121.c` | `test_din70121` 74 | built (`analyze92`/`93` / B2) |
| DIN autonomous session SM (states/timers/retries) | `din_session.c` | `test_din_session` 42 | built (`analyze93` F / B2) |
| Live transport glue (IPv6/UDP/TCP/deframe/TLS-decision/SM) | `v2g_net.c` | `test_v2g_net` 90 | built (`analyze94`) |
| Live stack: lwIP netif + raw pcb + mbedTLS bio bridge | `v2g_stack.c` | `test_tls_mbedtls` 21 | built (vendored, `analyze97`) |
| PnC CA cert store → `x509_crt_parse`/`conf_ca_chain` | `ca_store.c` | `test_ca_store` 45 | built (`analyze96`) |
| HW-RNG `f_rng` (STM32 `0x50060800`, not ctr_drbg) | `hw_rng.c` | — | built (`analyze94`/`100`) |
| Controller glue (`ccs2_evse`/`fill_current_ctrl`/`demand`/`evse_present_voltage`) | `ccs2.c` | `test_ccs2` 23 | built (`analyze92` / B2) |
| Vendored mbedTLS 2.28.9 + lwIP 2.1.4 (byte-faithful config) | `third_party/`, `mbedtls_config.h`, `lwipopts.h` | `analyze97` 63 | built (`analyze97`–`100`) |

CHAdeMO side (built earlier, inert): `can`/`chademo` (H100/101/102 RX, H108/109 TX), `charge_stm` (shadow,
byte-exact state-17 guard), `current_ctrl` (shadow setpoint), `hv`/`adc`/`nv_cal`/`spi4` (factory-cal HV
measurement), `rcc`/`gpio`/`tick`. Full host suite **722 checks / 0 failures** (16 tests); built-image disasm
`verify_ccs2.py` **222 checks / 0** (last verified at the engagement-reference fix `c8fc16a`; ARM text 118508,
`CUSTOM.UPG` 132102 B CRC OK). The B2 codec integration (`017577d`) + the engagement-reference fix (`c8fc16a`)
landed after the library-pivot milestone `91c938c`.

**Session sequence is wired end-to-end** (`din_session.c`): 1→2→3→6→7→8→9→10→11→12→13→0, timers
4000/120000/150000/40000/14000 ms, retry cap 20, CD modulo cadence, FAILED→shutdown + fault post. The
**EXI message content is now built** (B2): the 9 Req encoders + 9 Res decoders replace the former
ResponseCode-only advancement and `[? body]` placeholders. What remains partial is codec **fidelity**
(§2 G6–G8 + B2 `[?]` items) and **charge coordination** (§2 G10/G11), not the message skeleton.

---

## 2. Functional gaps (`[?]` — block a live SECC session)

These are the items that must be recovered/implemented for the adapter to interoperate with a real CCS2 EVSE.
All are **C013-decodable** (the stock encoder/decoder bytes exist) except where noted as bench-only.

### G1 — Req-side EXI root-event numbering — **RESOLVED + INTEGRATED (RE `analyze101`; B2 `017577d`)**  *(was critical path)*
**Resolution:** DIN does **not** use per-message 7-bit root events. All nine Req (and Res) messages ride a
**single 7-bit root event `0x4D` (77) + a 6-bit message-choice code** (encoder root `0x0806FA9C` → ev4d
`0x080706F6` → ev03 dispatcher `0x0806D6D2`; choice/subev/production/builder table in REPORT §5.9 EXI addendum).
The placeholder constants below are superseded; integration replaces them with root `0x4D` + the per-message
choice. *Historical gap:*
`din_session.c:16–24` — all nine Req root events are **symbolic placeholders**:
`SESSIONSETUP_REQ 0x01`, `SERVICEDISCOVERY_REQ 0x03`, `CPD_REQ 0x07`, `CABLECHECK_REQ 0x09`,
`PRECHARGE_REQ 0x0B`, `POWERDELIVERY_REQ 0x0D`, `CURRENTDEMAND_REQ 0x0F`, `WELDING_REQ 0x11`,
`SESSIONSTOP_REQ 0x13` — each marked `[?]`. The **Res-side** numbering IS recovered (`exi.h EXI_EV_*`,
`analyze93` E ground-truth: CurrentDemandRes `0x12`, CableCheckRes `0x05`, PreCharge `0x30`, SessionStop
`0x1e`, DC_EVSEStatus `0x16`, DC_EVSEChargeParam `0x15`, CPD wrapper `0x1d`, Welding `0x4f`). The **Req-side
encoder root events are not**. Decode from the C013 EXI **encoder root `0x0806FA9C`** + the 81-production
grammar table (TX leading-0x80 `0x08093C92`); the Req productions are the encode-side siblings of the
recovered Res decoders. **Impact:** without correct Req events the SECC rejects every request.

### G2 — Req-side EXI grammars / bodies — **RESOLVED + INTEGRATED (RE `analyze101`; B2 `017577d`)**  *(was critical path)*
**Resolution:** all nine Req bodies recovered (REPORT §5.9 EXI addendum): SessionSetup = EVCCID hexBinary6;
ServiceDiscovery = opt scope/category; CPD = 3-bit EnergyTransferMode + AC/DC choice (DC ev13 `0x0806CC3A`);
CableCheck/Welding = DC_EVStatus ev17 `0x0806A936`; PreCharge = DC_EVStatus + 2 PVT; PowerDelivery DIN ev2d =
varlen-enum ChargeProgress; SessionStop = empty. **CurrentDemandReq ev11 full grammar** recovered incl. the
opt EVMaximum* limits / BulkChargingComplete@0x40 / ChargingComplete@0x48 / RemainingTime*; target-current
@0x14 (factor @0x18), target-voltage @0x64 (factor @0x68) — packer `0x0802C2CE`. Integration adds the 8 missing
Req encoders + corrects the CD-req offsets. *Historical gap:*
`din_session.c:34` — the TX hook produces framing (8-byte V2GTP + leading `0x80` + 7-bit event) but
**`[? body]`** for all Req except CurrentDemand. `din70121.h` exposes exactly **one** Req grammar encoder:
`din_cd_req_encode_exi` (CurrentDemandReq). **Missing Req encoders (8):** SessionSetupReq, ServiceDiscoveryReq,
ChargeParameterDiscoveryReq, CableCheckReq, PreChargeReq, PowerDeliveryReq, WeldingDetectionReq, SessionStopReq.
Even CurrentDemandReq's full field set is partial — `din70121.c:259` "EVMaximum* limits, BulkChargingComplete,
RemainingTime* is `[?]` (E §3 partial)". Decode the encode-side productions from the same grammar table
(application field maps already located, e.g. CurrentDemandReq `0x0802C2CE`). **Impact:** no valid Req bodies.

### G3 — Res-side full field lists for handshake messages — **RESOLVED + INTEGRATED (RE `analyze102`; B2 `017577d`)**
**Resolution:** five Res grammars recovered (REPORT §5.9 EXI addendum): SessionSetupRes ev41 `0x08062B1E`
(RC + EVSEID + opt timestamp); ServiceDiscoveryRes ev3d `0x08063370` (RC + ChargeServiceList + ServiceList +
opt EnergyTransferModeList); CPDRes **ev0c `0x08065BFC`** (RC + 1-bit processing flag @body+1 + AC/DC choice →
DCparam ev15 `0x080650D2` 8-PVT limits); PowerDeliveryRes ev2e `0x08063DBA` (RC + EVSEStatus choice →
DC_EVSEStatus); WeldingDetectionRes ev4f `0x08062754` (RC + DC_EVSEStatus + EVSEPresentVoltage PVT). Leading
1-bit gate convention + subev dispatch (SessionSetup=30/ServiceDiscovery=26/CPD=8/PowerDelivery=20/Welding=34/
SessionStop=32/CableCheck=2/PreCharge=22/CurrentDemand=14). **Corrections:** CPD is ev0c (not the ev1d
wrapper); SessionStopRes = ev43 `0x08062A7E` (not ev1e). Integration adds 5 Res decoders + explicit RX cases.
*Historical gap:*
`din_session.c:262–290` (default branch) — SessionSetupRes / ServiceDiscoveryRes / ChargeParameterDiscoveryRes /
PowerDeliveryRes / WeldingDetectionRes advance on **ResponseCode only** (`read_rc`, first 5-bit field);
"full field lists partial (E §3)". Full grammar decoders exist only for CurrentDemandRes / CableCheckRes /
PreChargeRes / SessionStopRes / DC_EVSEStatus. The decoder **addresses are already located** (`analyze93` E) —
e.g. CPD wrapper `0x080650AC`, DC_EVSEChargeParam `0x080650D2` — so the full field lists are decodable.
**Impact:** handshake Res payloads (charge params, service/payment options, EVSE processing state) are not
extracted; the session advances blind on ResponseCode.

### G4 — DIN-vs-ISO `DC_EVSEStatus` layout — **RESOLVED + INTEGRATED (RE `analyze103`; B2 `017577d`)**
**Resolution:** `0x0806259E` is a **single merged grammar with NO DIN/ISO flag**. Order =
isolation_status(2) → status_code(4) → **NotificationMaxDelay(u32, MANDATORY — present in DIN)** →
notification(2); isolation gated by a **2-bit** presence code E0 (0=present/1=absent/≥2=−110); 22 fixed bits
+ one u32, 12 one-bit gates all 0; out struct isolation@0/present@1.bit0/code@2/maxdelay@+4/notif@8. The
replica's 1-bit presence gate, notification-before-code order, and hardcoded maxdelay=0 are all wrong;
integration rewrites `din_dc_evse_status_decode`. *Historical gap:*
`din70121.c:127,150` — byte movements confirmed (2-bit + 4-bit enums + u32 + 1-bit gates) but "DIN-vs-ISO
layout / exact gate sequence is `[?]` (E §5)"; `notification_max_delay = 0` ("ISO u32 not present in DIN `[?]`").
Decoder `0x0806259E` (ev `0x16`). **Impact:** EVSE notification/status-code attribution may be wrong; the
isolation field (load-bearing) is extracted but its exact wire gate is unconfirmed.

### G5 — `EVSEIsolationStatus` → charge-stm level 3/4 mapping — **RESOLVED + INTEGRATED (RE `analyze103`; B1/B2; premise corrected)**
**Resolution:** the premise "DIN wire isolation → internal level 3/4" is **FALSE** — there is no such
conversion. **Three distinct signals:** (a) **DIN wire isolation** (session byte `0x2000C808`, 0..3) gates
only the session CableCheck rule `0x080365A4` (==1 advance/==0 retry/≥2 fault16 — replica already correct);
(b) **EVSE charge-phase status** meas+0x3D1E halfword (3=CableCheckRes/4=PreChargeRes/7=error) is what the
engagement guard `0x0804AF08` `==4` tests; (c) **CHAdeMO hardware isolation level** struct `0x20000868`
(getter `0x0805206C`, 0..3 **never 4**) is what the CurrentDemand interlock `==3` reads. Feeding DIN isolation
(≤3) into `==4` can **never** fire — the charge-abort root cause. Integration splits the replica's single
`isolation` into `evse_phase_status` (engage ==4) / `chademo_isolation_level` (CD ==3) / `din_isolation`
(session only); PreChargeRes sets phase_status=4. precharge_flag = meas+0x23F = `0x200077AF`. *Historical gap:*
`ccs2.c:191` "exact 3/4 mapping gated (Agent D §7)"; `din_session.h` "isolation … raw; 3/4 level mapping gated".
The raw enum is `0 invalid / 1 valid / 2 warning / 3 fault` (`din70121.h`), but the `charge_stm` engagement guard
requires `isolation == 4` (REPORT §5.17). The mapping from the DIN `EVSEIsolationStatus` wire value to the
internal level 3/4 is **not recovered**. Decode the C013 `ccs2_evse`/charge-stm isolation path. **Impact:** the
byte-exact state-17 engagement guard cannot pass on a live session until this mapping is correct.

### G5b — state-17 engagement voltage reference (`ress_vol`) — **RESOLVED + FIXED (`analyze104`; `c8fc16a`)**
A correctness bug found **beyond** the original audit (via the ccs32clara-chademo prior-art comparison): the
replica used `ress_vol = veh->target_voltage` (H102 TargetBatteryVoltage, 410 V). **C013's actual reference is
the EVSE PresentVoltage**, proven byte-exact: guard `0x0804AF08` compares `outvol=p[+0x16]` against `sl`;
`sl = din_scale(meas+0x3D18 raw, meas+0x3D1A factor)` computed at `0x0804AADA–0x0804AAEE` (sp-slots set at
`0x0804917C/74`); the dual log `0x0804AB40` (fmt `0x080AB80C`) prints `ress_vol`(sl) and
`TargetBatteryVoltage`(`p+0x1da`) as **separate** values. During precharge the EVSE reports the *battery*
voltage (~364 V on a ZE1), not the 410 V target — so the target reference put the window at [400,415],
unreachable at ~364 V → state-17 stalls to its 424-tick timeout → 450 (the C009 abort). **Fix:** `charge_stm`
now uses `in->evse_present_voltage`, wired `ccs2_evse()->evse_present_voltage = din_evse_present_voltage_v()`
→ `main.c`; the pure guard math is unchanged. State-19 (`0x08044608`) uses `sl` as a dwell-timeout counter
(target only logged) — its voltage compare is a noted replica simplification. ZE1 regression added
(`test_charge_stm` 47→55). **Impact:** resolved — the engagement guard now references the correct voltage.

### G6 — CD secondary re-send interval set-site `[?]`
`din_session.c:158` — "SECONDARY: ctx+0x44 interval gated ctx+0x46==1 (`@0x08039698`), parameterized." The
**set-site** (where ctx+0x44/0x46 are written) is `[?]`; currently defaulted (`din_session_set_fp`,
`cd_interval`). Primary cadence `meas[0xC]%fp` IS recovered (`0x080396F6`, fp getter `0x08088B6C`).
**Impact:** secondary CurrentDemand re-send timing is parameterized, not byte-faithful.

### G7 — DIN session skips states 4/5 `[?]`
`din_session.c:273` — "3→6 (DIN skips PaymentSelection/ContractAuth 4/5 `[?]`)". The replica assumes DIN skips
ISO ServicePaymentSelection (4) + ContractAuthentication (5). Whether DIN truly skips them (vs a DIN variant)
is unconfirmed. **Impact:** sequence correctness for DIN-only SECCs; low risk (DIN DC is EIM, no PnC contract).

### G8 — minor grammar partials `[?]`
- CurrentDemandRes optional max-limit choice chain (`din70121.c:181,189,196`; state `0x23` readBits3 /
  `0x24–0x25` readBits2) — "recovered wire order `[? exact grammar]`".
- DIN PhysicalValueType **unit enum** A/V values (`din70121.c:276,283` — "A (ampere) `[?]", "V (volt) `[?]"`).
- 150 s timeout clean compare site (`din_session.c:121` — "clean cmp not found `[?]`; outer guard").
- B2 codec `[?]` fidelity items still marked in source: Req encoder **leading/inter-field gate sequences**
  (SessionSetupReq ev40 prologue `din70121.c:366`, PreChargeReq inter-field `:427`, CPDReq ev0b/ev13 +
  `EnergyTransferMode DC=3` enum `:482–492`); **ServiceDiscoveryRes list sub-grammars** (`:637`,
  `din70121.h:237` — structurally consumed, not decoded); **PVT unit enum** A/V (`:301`, A=1/V=3 guessed);
  CPDRes AC-sched choice (`:669`); per-builder **SessionID negotiation** (1-byte `0x00` placeholder,
  `din_session.h:99`, `exi.h:70`).
**Impact:** optional-field / unit / gate fidelity; inert-safe until bench-validated.

### G10 — CCS PreCharge ↔ CHAdeMO car-contactor stall coupling `[?]`  *(charge coordination)*
Surfaced by the ccs32clara-chademo prior-art comparison. The replica's `din_session` advances
PreCharge→PowerDelivery **immediately on `rc_ok`** (decoupled from the car side). The known-working prior art
**stalls `PreChargeReq`** until the CHAdeMO car contactors close (`chademoInterface_preChargeCompleted()` →
`CarContactorsClosed`; `sendAgain=true` even when the CCS precharge voltage difference is small, ≤30 s). Without
this coupling the EVSE can be told "precharge finished" before the car is ready to accept current. **To scope:**
decode C013's PreChargeRes→PowerDelivery gating against the CHAdeMO contactor feedback (H102.VehicleStatus /
`get_precharge_relay`) — does C013 stall the CCS PreCharge loop on the car contactor, and with what timeout?
**Impact:** charge-coordination correctness; belongs to the session-coupling / gated power-drive layer.

### G11 — output-current ramp + undersupply limit `[?]`  *(charge coordination)*
`current_ctrl` replicates the C013 state-30 min/cap law with **no ramp limiter** (byte-exact — the state-30
block `0x08044D42` has none). The prior art ramps the CHAdeMO current request **+4 A/100 ms up / −10 A/100 ms
down** and limits undersupply. The C013 log shows periodic `setpara_maxevsecurrent`, suggesting ramping lives
**elsewhere** (a periodic set-parameter path, not the state-30 law). **To scope:** decode C013's
`setpara_maxevsecurrent` / current-setpoint slew path — where and how fast the commanded current ramps, and
whether an undersupply/derate limit exists. **Impact:** smooth current delivery to the car; gated power-drive
layer. (The voltage-estimation curve is **moot for the CCS2 engagement reference** — G5b proved C013 uses the
measured EVSE present voltage — but the CHAdeMO-side precharge target may still need a battery estimate.)

### G9 — SECC-peer wire convention capture `[?]`  **(bench-only)**
REPORT §5.9 line 964 — the actual SECC peer's wire behavior (real EVSE message ordering/option choices) needs a
**bench capture**, not a C013 decode. **Impact:** final interoperability validation; requires hardware.

---

## 3. Fidelity-reference `[?]` notes (NOT functional blockers)

The vendored **standard** lwIP 2.1.4 + mbedTLS 2.28.9 are wire-interoperable; these notes document stock
deviations for reference only and do **not** block a live session:

- lwIP exact patch level (2.1.2/2.1.3-era), `MEMP_NUM_TCP_SEG` pool size, initial iss RAM value `[?]`
  (REPORT §5.9 / `analyze98`). Stock is dual-stack; the adapter is IPv6-only (functional subset).
- mbedTLS version ≈2.16–2.28 `[?]`, vendor-modified `[?]` (`analyze99`/`100`). C013 uses a **17-state** handshake
  enum (OVER=0x10) + derive_keys-in-cert-verify; upstream 2.28.9 uses the standard 16-state SM — same wire protocol.
- ND6 pre-RA reachable/retransmit `[?]` (`analyze96`); C013 NS-receive DELAY/counter=5 vs lwIP STALE=3 — internal
  SM quirk, wire-interoperable.

## 4. GATED LAST — asserted power-stage drive (intentional)

`charge_stm` engagement (contactor/relay GPIO sequencing), BCB PD11 drive, +24 V power-fail queue. These stay
**GATED behind a compile-time safety flag** until the charge controller is bench-validated against the decoded
laws (REPORT §5.17/§5.18/§5.20/§5.21/§5.5c). Not a gap to close now — the final layer.

---

## 5. Next-build-step scoping (recommendation)

The critical-path **RE + integration are DONE** — G1–G5 recovered byte-exact (`analyze101`/`102`/`103`) and
**built** (B2 `017577d`); the engagement reference is corrected (G5b, `analyze104` / `c8fc16a`). The former
steps 1–3 (Req encoders / Res field lists / DC_EVSEStatus + three-signal split) are **complete**. What remains,
in priority order toward a *safe charge*:

1. **Charge-coordination RE + design (G10/G11)** — decode C013's PreChargeRes→PowerDelivery gating against the
   CHAdeMO car-contactor feedback (does C013 stall the CCS PreCharge loop on `CarContactorsClosed`, with what
   timeout?) and the `setpara_maxevsecurrent` / current-setpoint slew path (ramp rate + undersupply limit).
   This is the highest-value remaining RE: it determines whether the session can hand off to a real charge
   safely. Read-only decode first; any replica coupling/ramp change stays inert until bench-validated.
2. **Codec fidelity partials (G6/G7/G8 + B2 `[?]`)** — Req gate sequences, ServiceDiscovery list sub-grammars,
   CDRes optional-choice chain, PVT unit enums, SID negotiation, CD secondary set-site, DIN 4/5 skip, 150 s
   compare site. Inert, C013-decodable, host-testable; can proceed in parallel with step 1. Polish, not a
   live-session blocker.
3. **Bench validation (G9)** — live SECC session capture (hardware: ESP32-S3 / Arduino Mega bench) to confirm
   real EVSE message ordering/option choices + the live lwIP/mbedTLS TCP-connect/TLS-handshake on hardware.
4. **GATED power-stage drive (LAST, §4)** — asserted contactor/relay GPIO sequencing + BCB PD11 + +24 V
   power-fail queue, behind a compile-time safety flag, **after** the controller is bench-validated against the
   decoded laws (REPORT §5.17/§5.18/§5.20/§5.21/§5.5c).

Steps 1–2 are read-only RE + inert implementation + host tests + build/`verify_ccs2`/UPG re-wrap (no power
drive); step 3 needs hardware; step 4 is the final gated layer. This keeps the asserted power-stage drive
GATED LAST throughout. **Critical path:** the codec is essentially complete; the path to "runs a safe charge"
is coordination (1) → bench (3) → gated drive (4), with fidelity (2) as parallel polish.
