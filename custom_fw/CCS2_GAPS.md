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
old target reference made the engagement window unreachable during precharge (the C009 abort). The
**charge-coordination** gaps surfaced by the prior-art comparison are now **RE-resolved** (`analyze105.py`):
**G10** PreCharge↔car-contactor coupling lives in the CHAdeMO charge stm (states 15/16 wait VehicleStatus bit3 +
current-request>0, 8s/4s; 18/19 inner precharge relay PB10) and is **already replicated** in `charge_stm`;
**G11** current ramp is a slow **+20 A/minute** ramp on the requested EVMaximumCurrentLimit (`meas+0x28C`,
`0x0804BB54`), distinct from the instantaneous per-tick min/cap law — now **BUILT** as the inert shadow
`current_ramp.c` (byte-exact, host-tested). The codec **fidelity partials** (G6–G8 + the B2 `[?]`
gate-sequence / list-sub-grammar / optional-choice / unit-enum / SID-negotiation items, §2) are now
**RE-resolved + integrated** (`analyze106.py`/`106b`/`106c`): the CDRes optional max-limit **nested choice
chain** (ev12 `0x0806471E` states `0x23`/`0x24`/`0x25`), the PreChargeReq missing inter-field gate, the CPDReq
ev0b/ev13 prologue, the SessionSetupReq/CPDRes prologues (confirmed), the ServiceDiscoveryRes list grammar
(documented), the G6 CD secondary **one-shot** cadence (read-site `0x08039684`), the G7 DIN 4/5 skip
(confirmed), the G8 150 s outer-guard, the PVT unit mechanism, and **SessionID negotiation** (`set_sid` +
`ccs2_rx_exi` adoption). **What remains:** (i) the bench-only **G9** live SECC interop capture; and (ii) the
**GATED-LAST** asserted power-stage drive (§4). The library network/crypto layers are **done** (vendored,
byte-faithful config). Full host suite **817 / 0**; `verify_ccs2.py` **222 / 0**.

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
| DIN70121 meas + pow10 scale + B2 message codec (9 Req / 9 Res) | `din70121.c` | `test_din70121` 117 | built (`analyze92`/`93` / B2 / `106`) |
| DIN autonomous session SM (states/timers/retries) | `din_session.c` | `test_din_session` 56 | built (`analyze93` F / B2 / `106`) |
| Live transport glue (IPv6/UDP/TCP/deframe/TLS-decision/SM) | `v2g_net.c` | `test_v2g_net` 90 | built (`analyze94`) |
| Live stack: lwIP netif + raw pcb + mbedTLS bio bridge | `v2g_stack.c` | `test_tls_mbedtls` 21 | built (vendored, `analyze97`) |
| PnC CA cert store → `x509_crt_parse`/`conf_ca_chain` | `ca_store.c` | `test_ca_store` 45 | built (`analyze96`) |
| HW-RNG `f_rng` (STM32 `0x50060800`, not ctr_drbg) | `hw_rng.c` | — | built (`analyze94`/`100`) |
| Controller glue (`ccs2_evse`/`fill_current_ctrl`/`demand`/`evse_present_voltage`) | `ccs2.c` | `test_ccs2` 23 | built (`analyze92` / B2) |
| Vendored mbedTLS 2.28.9 + lwIP 2.1.4 (byte-faithful config) | `third_party/`, `mbedtls_config.h`, `lwipopts.h` | `analyze97` 63 | built (`analyze97`–`100`) |

CHAdeMO side (built earlier, inert): `can`/`chademo` (H100/101/102 RX, H108/109 TX), `charge_stm` (shadow,
byte-exact state-17 guard), `current_ctrl` (shadow setpoint), `current_ramp` (shadow +20 A/min
EVMaximumCurrentLimit ramp, G11), `hv`/`adc`/`nv_cal`/`spi4` (factory-cal HV measurement), `rcc`/`gpio`/`tick`.
Full host suite **817 checks / 0 failures** (17 tests); built-image disasm `verify_ccs2.py` **222 checks / 0**
(ARM text 119012, `CUSTOM.UPG` 132102 B CRC OK). The B2 codec integration (`017577d`) + the engagement-reference
fix (`c8fc16a`) + the coordination decode (`5d9ecc4`) + the codec-fidelity partials (`analyze106`) landed after
the library-pivot milestone `91c938c`.

**Session sequence is wired end-to-end** (`din_session.c`): 1→2→3→6→7→8→9→10→11→12→13→0, timers
4000/120000/150000/40000/14000 ms, retry cap 20, CD modulo cadence, FAILED→shutdown + fault post. The
**EXI message content is now built** (B2): the 9 Req encoders + 9 Res decoders replace the former
ResponseCode-only advancement and `[? body]` placeholders. **Charge coordination is complete** (G10 already
faithful in `charge_stm`; G11 ramp built in `current_ramp`). **Codec fidelity is now resolved** (`analyze106`,
§2 G6–G8 + B2 `[?]` items): the CDRes optional-choice chain, Req gate sequences, PVT unit mechanism, and
SessionID negotiation are byte-exact + host-tested. What remains is bench interop (G9) + the gated power drive.

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

### G6 — CD secondary re-send interval set-site — **RESOLVED + INTEGRATED (RE `analyze106`)**
**Resolution:** the secondary cadence **read-site** is decoded byte-exact (`0x08039684`–`0x080396C6`): gate
`ctx+0x46==1` (arm flag); `now=gettick` (`0x0808A236`); anchor `ctx+0x40`; skip if `anchor>=now`;
`elapsed=now-anchor`; interval `ctx+0x44` (u16); fires when `elapsed>=interval` (`cmp r1,r0; bhi skip` — a
**`>=`** compare); then **CLEARS `ctx+0x46`** (ONE-SHOT, not periodic), re-sends CD (`bl 0x08034C30`), re-arms
`ctx+4=4000` (resp-wait) + `ctx+0x14=now` (last_req) + state=10. The replica `din_session_step` now uses `>=`
and clears `cd_resend_active` after firing; the arm is parameterized via `din_session_arm_cd_resend(interval,
now)` (sets `ctx+0x44`/`0x40`/`0x46`, mirroring the stock arm; interval 0 disarms). Primary cadence
`meas[0xC]%fp` IS recovered (`0x080396F6`, fp getter `0x08088B6C`). Host-tested (`test_cd_secondary_oneshot`:
`>=` boundary, one-shot disarm, no re-fire, re-arm, interval-0 disarm). **Impact:** resolved — the secondary
re-send is byte-faithful (one-shot `>=` cadence); the arm interval remains a runtime parameter like `fp`.

### G7 — DIN session skips states 4/5 — **CONFIRMED (RE `analyze106`)**
**Resolution:** the RX transition engine `0x080353B2` dispatch (`tbh 0x08035444`, gate `cmp #0xe`) confirms
DIN advances **3→6** directly: ServicePaymentSelection (4) + ContractAuthentication (5) are **ISO-only** and
skipped by the DIN ServiceDiscoveryRes path. The replica `din_session_rx` (3→6) + the `din_session.h` state
comments ("ISO-only … DIN skips") are correct. **Impact:** resolved — sequence faithful for DIN-only SECCs
(DIN DC is EIM, no PnC contract).

### G8 — minor grammar partials — **RESOLVED + INTEGRATED (RE `analyze106`/`106b`/`106c`)**
- **CurrentDemandRes optional max-limit choice chain** (ev12 `0x0806471E`) — decoded byte-exact: a **NESTED
  optional-element choice** (NOT per-field presence bits), fixed order Current→Voltage→Power. State `0x23`
  readBits(3): 0=EVSEMaximumCurrentLimit PVT(+0x2c,flag+0x34)→`0x24`, 1=VoltageLimit(+0x38,flag+0x40)→`0x25`,
  2=PowerLimit(+0x44,flag+0x4c)→state4, 3=end (≥4→err). `0x24` readBits(2): 0=Voltage,1=Power,2=end (≥3→err).
  `0x25` readBits(2): 0=Power,1=end (≥2→err). Replica `din_cd_res_decode_exi` rewritten with the choice chain +
  `evse_max_{current,voltage,power}_present` flags + `evse_max_power`/`_f` storage. Host-tested
  (`test_din70121`: all-absent/Current-only/Voltage-only/Power-only/all-three/Current+Power + invalid-choice
  `EXI_ERR_EVENT`).
- **DIN PhysicalValueType unit enum** A/V — the wire **mechanism** is byte-proven (encoder `0x0806A3AC`: gate,
  gate, Multiplier(3-bit=mult+3), gate, Unit choice(2)[0=present→gate,Unit(4-bit),gate | 1=absent], gate,
  Value(signed), gate, EE gate). Unit is a **caller-set 4-bit schema enum**; A=1/V=3 are schema-derived (the
  exact constants were not located in the app builder — documented honestly, not byte-proven). The replica
  `exi_read_pvt`/`exi_write_pvt` omit the internal gates (a self-consistent simplification, host-round-tripped).
- **150 s timeout compare site** — `analyze106b` scanned the poll region `0x08038000`–`0x0803A000` for a
  `movw #0x249F0` (150000) immediate / `ctx+C` compare and found **none**; the clean compare is not a simple
  immediate there. Modeled as an **OUTER GUARD** that never fires before the 120 s total (`ctx+8`, compare
  `0x08038458`/`0x0803874E`, gate `ctx+0x2A`). Documented in `din_session_step`.
- **Req encoder gate sequences** — SessionSetupReq ev40 `0x0806ABEA` prologue **CONFIRMED** (gate, gate,
  EVCCID varlen, gate, gate(EE) = 4 gates; replica already matched). **PreChargeReq ev2f `0x0806B4DE`**: the
  gate between DC_EVStatus and EVTargetCurrent was **MISSING** — added (now 4 gates: gate, DC_EVStatus, gate,
  EVTargetCurrent, gate, EVTargetVoltage, gate(EE)). **CPDReq ev0b `0x0806CEF0`** prologue decoded: gate, gate,
  EnergyTransferMode(3-bit caller-set, DC=3 schema-derived), gate, AC/DC choice(2)[0=AC `0x0806CE20`,
  1=DC_EVChargeParameter ev13 `0x0806CC3A`, 2=`0x0806CC32`], gate(EE); DIN takes choice 1. Replica prologue
  corrected. Host-tested (`test_din70121` PreChargeReq/CPDReq body walks: gate positions + PVT values + ETM/choice).
- **ServiceDiscoveryRes list sub-grammars** (ev3d `0x08063370`) — grammar decoded: state `0x8c` gate,gate,RC(5),
  gate → `0x8d` gate,ChargeServiceList(`0x0806327A`,struct+2,count≤5) → `0x8e` gate,ServiceList ev39
  (`0x0806316A`,struct+0xc) → `0x8f` choice(2)[0=opt EnergyTransferModeList(`0x0806A192`,struct+0x64,count≤8,
  flag+0x308),1=absent]→state4 gate. Replica reads RC (lists unused; raw body preserved `memcpy meas+0x37e0`);
  full list **consumption deferred** (not needed for the DIN DC handshake) — documented, not a blocker.
- **CPDRes AC-sched choice** (ev0c `0x08065BFC`) — **CONFIRMED**: state `0x74` sched-choice(2)[0=AC sched ev35
  `0x08065B62`, 1=DIN empty `0x08065368`], `0x75` AC/DC-choice(2)[0=`0x08065296`, 1=DCparam ev15 `0x080650D2`,
  2=`0x080650AC`]; DIN takes choice 1 on both. Replica correct.
- **SessionID negotiation** — SessionSetupRes ev41 `0x08062B1E` body = RC(5)+EVSEID(varlen clamp 0x20)+opt
  timestamp; the SID is **HEADER-ONLY** (gid `0x6c`). The stock TX wrapper `0x08034C30` copies the 8-byte
  negotiated SID (`r5+0x1f7`→`r4[0..7]`, len=8) into every post-setup document; SessionSetupReq uses a 1-byte
  `0x00` placeholder. Replica wired: `din_session_set_sid` (clamp `DIN_SID_MAX`, ignore zero-len) + `ccs2_rx_exi`
  adopts the SID from the SessionSetupRes header **before** `din_session_rx` (so the emitted ServiceDiscoveryReq
  already carries it); `default_tx` copies `sess.sid` into all 9 Req builders. Host-tested
  (`test_din_session.test_sid_negotiation`: placeholder, 8-byte adoption, post-setup carry, clamp, zero-len ignore).
**Impact:** resolved — optional-field / unit / gate / SID fidelity is byte-exact (mechanism) + host-tested;
the PVT unit enum constants + ETM DC=3 are schema-derived (documented), and ServiceDiscovery list consumption
is deferred (unused by DIN DC). Inert-safe; bench interop (G9) remains.

### G10 — CCS PreCharge ↔ CHAdeMO car-contactor coupling — **RESOLVED** (RE `analyze105`)
Decoded byte-exact (`analyze105.py`). The coupling lives in the **CHAdeMO charge stm**, NOT in a stall of the
DIN EVSE-side `PreChargeReq` loop (so the prior-art ccs32clara "stall PreChargeReq on `CarContactorsClosed`"
pattern is **not** how C013 does it):
- **state 15** (`0x0804A284`): `ldrb p[+0x1de] ; ubfx #3,#1` = **H102.VehicleStatus bit3 = EV contactor closed**;
  log `0x080AB1DC` *"15 case, 8s timeout after Switch(d2)=ON! but EV contactor is not closed"*.
- **state 16** (`0x08043232/36`): same `ubfx` bit3; log `0x080A83F0` *"16 case, 4s timeout … EV contactor is not
  closed"*; timeout counter `p[+0x1b8]` vs `0x7d` (`0x080432A4`). A second gate waits
  **H102.ChargingCurrentRequest > 0 A** (log `0x080AB4A0`, *"8s timeout … not more than 0A"*).
- **state 17** (`0x0804AB98`): log `0x080AB894` *"EVSE outvol[%lu],p->ress_vol[%lu] **wait until CCS precharge
  finished**! … get_precharge_relay=%d"* — the engagement guard (G5b) waits for the CCS precharge voltage match;
  wait counter `p[+0x14]` vs `0xc8` (`0x0804ABA6`).
- **get_precharge_relay** (`0x080525D8`→`0x080884B0`): `GPIOB(0x40020400) IDR bit10` = **PB10 input** — the
  adapter's **inner** precharge-relay feedback (hardware GPIO, distinct from the car contactor).
- **set_precharge_relay** (`0x080524FC`): drive relay to `r0&1`, poll PB10 until it matches, timeout `0x1F40` +
  retry counter `[0x200008A8]`; mismatch → fail → terminate session (states 18/19).

**Conclusion:** C013 sequences **car-contactor-close (15/16, VehicleStatus bit3, 8s/4s) → CCS-precharge voltage
engagement (17) → inner precharge-relay close (18/19, PB10)**. The DIN EVSE session advances
PreCharge→PowerDelivery on `rc_ok` (`phase_status=4`), which is the engagement **gate** — it does not itself stall
on the car contactor. **The replica `charge_stm` ALREADY models this** (state 15 `ev_contactor`, 16
`current_request>0`, 18 `precharge_relay`); the earlier "decoupled" worry was mis-scoped. **Impact:** resolved —
no new coupling code needed; the sequence + timeouts are confirmed faithful (the asserted PB10/d2 GPIO drive
remains the gated layer, §4).

### G11 — output-current ramp + undersupply limit — **RESOLVED + BUILT** (`analyze105` → `current_ramp.c`)
Decoded byte-exact (`analyze105.py`). C013 has **two distinct current paths**:
1. **Per-tick CurrentDemand setpoint** (`0x08044D42`, replica `current_ctrl`): `min(request, avail)` capped by
   EVSE max — instantaneous, **no ramp** (byte-exact, already replicated).
2. **Periodic EVMaximumCurrentLimit ramp** (`0x0804BB54`) — **replicated** in `current_ramp.c` (inert shadow):
   - **Ramp ceiling** `[0x200007AC]` = `din_scale(EVSE max current, meas+0x3D20/22)` (`0x0804B726–0x0804B73A`).
   - **Ramped setpoint** `meas+0x28C` (`0x200077FC`), **init 20 A** at state-17 (`0x0804ABCA movs #0x14`).
   - Check every 10 ticks (`phase_cnt%10`); the **+20 A (`0x14`) step** is gated on **`phase_cnt%6000==0`**
     (`movw #0x1770`=6000, `0x0804BB84`) = **6000 ticks = 60 s = 1 minute @100 Hz** — matching log `0x080AC0F0`
     *"CurrentDemand phase, every n minute adjusts current limintation … pMsgPfm->setpara_maxevsecurrent[%lu]"*
     (loaded base `0x080AC080`+`0x70`, `0x0804BBAA`).
   - **Up-ramp:** setpoint += 20, clamped to ceiling `[0x200007AC]`, **±5 A deadband** around the request
     (`0x0804BB76–82`). **Down-path:** ±25 A deadband, gated `p[+0x64] >= 600` (`0x0804BBBC`).
   - **CurrentDemandReq EVMaximumCurrentLimit** = `min(ramped meas+0x28C, din_scale(EVSE max))`
     (`0x0804EA94–9C`: `ldrh [r6,#0x28c] ; cmp r0,r5 ; bhi keep ; mov r5,r0`).

**Conclusion:** C013 ramps the **requested EVMaximumCurrentLimit** up **+20 A per minute** (slow inrush limit),
never above the EVSE-reported max, init 20 A. This is **NOT** the prior-art +4 A/100 ms fast ramp.
**BUILT** (`current_ramp.c`, `test_current_ramp` 38 checks): byte-exact `0x0804BB54` step law — init 20 A,
`phase_cnt%10` gate, FINE +20 A/`phase_cnt%6000` (±5 A deadband) / COARSE +20 A/10 ticks (±25 A deadband,
`p[+0x64]>=600`), 32-bit unsigned deadband math (the coarse +25 bound is `(setpoint−25)+50`, wrapping
consistently at the 20 A init), ceiling clamp, `EVMaximumCurrentLimit=min(ramped, ceiling)`. Wired inertly in
`main` CurrentDemand (target=`current_ctrl` avail, ceiling=cap, `phase_cnt`=p[+0x4] via `charge_stm_phase_cnt`);
re-init 20 A on state-30 entry; published `cc_ramp_setpoint`/`cc_max_limit` (SWD) + `meas+0x28C`. With EVSE
stubs 0 the ceiling is 0 → no step, `max_limit` 0 (no limit asserted). Communication-side, **no GPIO**; the
asserted power drive stays gated (§4). (The voltage-estimation curve is **moot for the CCS2 engagement
reference** — G5b proved C013 uses the measured EVSE present voltage.)

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
**built** (B2 `017577d`); the engagement reference is corrected (G5b, `analyze104` / `c8fc16a`);
**charge coordination is complete** (`analyze105`): G10 car-contactor coupling is already replicated in
`charge_stm`, and the G11 +20 A/minute EVMaximumCurrentLimit ramp is **built** as the inert shadow
`current_ramp.c` (byte-exact `0x0804BB54`, `test_current_ramp` 38); and the **codec fidelity partials are
complete** (`analyze106`/`106b`/`106c`): G6 CD secondary one-shot cadence, G7 DIN 4/5 skip, G8 CDRes
optional-choice chain + Req gate sequences + PVT unit mechanism + 150 s outer-guard + ServiceDiscovery list
grammar + CPDRes AC-sched choice + SessionID negotiation — all byte-exact (mechanism) + host-tested
(`test_din70121` 117, `test_din_session` 56). The former steps 1–3 (Req encoders / Res field lists /
DC_EVSEStatus + three-signal split), the coordination decode, the inert ramp build, and the fidelity partials
are **complete**. What remains, in priority order toward a *safe charge*:

1. **Bench validation (G9)** — live SECC session capture (hardware: ESP32-S3 / Arduino Mega bench) to confirm
   real EVSE message ordering/option choices + the live lwIP/mbedTLS TCP-connect/TLS-handshake on hardware.
   The only remaining `[?]` items are bench-only (real SECC peer wire behavior) or documented simplifications
   (PVT unit enum constants / ETM DC=3 schema-derived; ServiceDiscovery list consumption deferred — unused by
   DIN DC; PVT internal gates omitted self-consistently).
2. **GATED power-stage drive (LAST, §4)** — asserted contactor/relay GPIO sequencing (incl. the decoded PB10
   inner precharge-relay drive + d2) + BCB PD11 + +24 V power-fail queue, behind a compile-time safety flag,
   **after** the controller is bench-validated against the decoded laws (REPORT §5.17/§5.18/§5.20/§5.21/§5.5c).

Step 1 needs hardware; step 2 is the final gated layer. This keeps the asserted power-stage drive GATED LAST
throughout. **Critical path:** the codec (skeleton + fidelity), coordination RE, and inert ramp are complete;
the path to "runs a safe charge" is bench (1) → gated drive (2). No inert communication-side RE/build work
remains on the critical path.
