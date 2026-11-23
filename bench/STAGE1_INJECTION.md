# Stage 1 — injected-signal fidelity bench (NO EVSE / NO car peers)

Goal: confirm the custom_fw measurement + protocol replicas are **byte-exact on real silicon** by
injecting known signals and reading them back over the USB CDC console. RDP:1 blocks SWD reads, so
the CDC bench console (`bench/cdc_console.py`) is the host observability path.

**Everything here is INERT.** The firmware drives NO power stage (the charge-stm is a shadow
controller; the engagement guard stays closed — `STM` reads `ENG 0 ACT 0`). This stage only exercises
measurement + communication. Power-stage drive is a later, GATED stage.

## Safety preamble (read first)

- HV side **disconnected**, bulk caps **discharged**. Low-voltage signal injection only.
- Common GND between the Arduino Mega and the adapter bench ground.
- **Adapter ADC pins are 3.3V-MAX, NOT 5V-tolerant in analog mode** (PA0/PA1/PA2/PC2/PB0/PB1, TTa
  structure). Every analog injection MUST be divided to **≤ 3.3V** before it touches the adapter.
  Verify with a multimeter at the adapter pin BEFORE connecting.
- **PD12 (CP) IS 5V-tolerant** (FT digital input) — a 0–5V PWM is fine; use a 1k series resistor.
- Do NOT connect a real EVSE or car in this stage.

## Bench console (firmware already flashed, cafe:4004)

```
nix-shell -p python3 python3Packages.pyserial usbutils --run \
  'sg dialout -c "python3 bench/cdc_console.py <cmd>"'
```
Read-only readback: `meas` `can` `net` `stm`. Software injection: `injc` (CAN), `inje` (Ethernet).
Run `help` for the device command list. (Old login sessions need `sg dialout`; ttyACM is root:dialout.)

### MEAS line format
```
HV <outvol> <raw> <cal> HVRAW <liveADC> CP <duty> <period> <upd> PP <mV> <raw> CPD <mV> <raw> BAT <mV> DL <b> PD11 <b> PLUG <b> ST <c>
```
- `HV outvol/raw` are cal-scaled (V / decivolts). **`cal=0` on this clone** (factory cal record at
  SPI4 0xFE000 fails magic/checksum) → those read 0. Use **`HVRAW`** (live ADC1−ADC2 accumulation)
  to observe HV injection without a cal.
- `CP duty` per-mille (percent×10), `period` µs (NOT Hz; f=1e6/period), `upd` update counter.
- `PP/CPD/BAT` mV + raw accumulator. `PLUG` PP presence (≤2146mV plugged, ≥2296mV unplugged).
- `ST` CP state char: `E` no PWM, `B` PWM present, `C` BCB engaged.

## A. Software injection (no wiring — already validated on silicon)

### CAN / CHAdeMO (`injc` → RX ring → chademo parse)
```
python3 bench/cdc_console.py injc 102 8 01 F4 01 14 00 00 00 00   # H102: status=1, 500V, 20A
python3 bench/cdc_console.py can                                 # -> H102 1 500 20 0 0 ... SEEN 001 FRESH 1
python3 bench/cdc_console.py injc 101 8 01 02 E8 03 D0 07 05 06   # H101: w2=1000 w4=2000 (LE)
python3 bench/cdc_console.py injc 100 8 11 22 33 44 55 66 77 88   # H100 raw
python3 bench/cdc_console.py stm                                 # -> ST 0 IL 00 ENG 0 ACT 0 (guard closed)
```
H102 byte map: b0=status, b1-2=TargetBatteryVoltage(V,LE), b3=ChargingCurrentRequest(A), b4/5=fault.
**Fidelity check:** readback fields == injected bytes (LE halfwords). Confirmed: 500V/20A parses exact.
Injecting vehicle frames alone CANNOT engage power (EVSE-side EXI handshake inputs hold 0).

### Ethernet (`inje` → v2g_net_rx_ethernet → lwIP demux)
```
python3 bench/cdc_console.py inje /tmp/eth_test.bin    # raw Ethernet frame -> OK INJE
python3 bench/cdc_console.py net                       # transport state (IDLE until SDP/TCP session)
```
Full SDP→TCP→TLS→EXI session fidelity is **Stage 2** (needs a real EVSE peer). Stage 1 confirms the
RX hook wiring (frame accepted, stack runs, no crash).

## B. Physical injection (Arduino Mega — `bench/stage1_inject/stage1_inject.ino`)

Flash the sketch to the Mega. Serial @ 115200: `C<duty>` CP per-mille, `P/D/B/H<0..255>` analog PWM,
`S` status. CP is pin 11 (1 kHz fast PWM); analog pins 9(PP)/10(CPD)/8(BAT)/7(HV).

### Adapter pin map (byte-derived RE)
| Signal | Adapter pin | ADC / capture | Mega pin | Conditioning |
|--------|-------------|---------------|----------|--------------|
| CP PWM | **PD12** | TIM4_CH1 AF2 capture | 11 | 1k series (5V-tolerant) |
| PP     | **PA2** | ADC3 ch2 (×16) | 9  | RC filter + ≤3.3V divider |
| CPD    | **PA0** | ADC3 ch0 (×8)  | 10 | RC filter + ≤3.3V divider |
| BAT    | **PC2** | ADC3 ch12 (×8) | 8  | RC filter + ≤3.3V divider |
| HV     | **PB0/PB1** | ADC1 ch8 / ADC2 ch9 differential | 7 | RC + divider; see note |

### B1. CP PWM → TIM4 capture
Wire: Mega **pin 11** → **1k** → adapter **PD12**; Mega GND → adapter GND.
```
Mega serial: C500     # 50.0% duty, 1kHz
cdc_console.py meas   # -> CP 500 1000 <upd> ... ST B
Mega serial: C50      # 5.0% -> ISO15118 digital mode (duty in [30,70])
cdc_console.py meas   # -> CP 50 1000 ...
Mega serial: C0       # no PWM (DC low) -> deglitch to 0
cdc_console.py meas   # -> CP 0 0 ... ST E
```
**Fidelity check:** `duty` == commanded per-mille (median-of-9 filtered), `period` ≈ 1000 µs
(validity window [950,1050]), `upd` increments. `ST` transitions E↔B. CP input is inverted on PD12
[inferred] — if duty reads (1000−commanded), that confirms the inversion.

### B2. PP / CPD / BAT analog → ADC3
Wire each Mega analog pin → **RC filter** (1k series + 10µF to GND) → **divider** (2k0 series + 3k3
to GND, ratio 0.623 → ≤3.11V from 5V PWM) → adapter pin. **Measure the adapter pin voltage with a
multimeter** (must be ≤3.3V).
```
Mega serial: P165     # PP ~2.0V (measure actual)
cdc_console.py meas   # -> PP <mV> <raw> ... PLUG 1  (<=2146mV -> plugged)
Mega serial: P205     # PP ~2.5V
cdc_console.py meas   # -> PP <mV> ... PLUG 0  (>=2296mV -> unplugged)
```
**Fidelity check:** MEAS `PP mV` ≈ multimeter voltage at PA2 (raw×3300/65520). `PLUG` crosses the
2146/2296 mV hysteresis. CPD (PA0, raw×3300/32760) and BAT (PC2, raw×6600/32760) likewise: inject a
known voltage, compare MEAS mV to the multimeter. The PP raw is 16×sum(ch2); BAT/CPD 8×sum.

**VALIDATED 2026-11-23 — bench-PSU route (preferred over the Mega PWM+divider).** A DC bench PSU set
to ≤3.3 V, through a series resistor (~220 Ω–1 k) with the PSU current limit ~20 mA, drives PA2
cleanly: its low output impedance overrides the adapter PP bias (the Mega divider's ~1.5 k Thevenin
could not). PP 1435 mV → `PLUG 1`; PP 2396 mV → `PLUG 0`; MEAS mV matched the multimeter at the pin on
both sides. **Pin-identification lesson:** the first connector pin tried idled at 2.6 V while PA2 idles
at ~2.39 V — a *different node*, so driving it never moved MEAS. Identify the real PP pin by its idle
voltage matching MEAS `PP mV` (~2.4 V), or drive a candidate at 2.0 V (current-limited) and watch MEAS
PP drop. **Never** put the PSU on the DC+ / DC− power pins (HV, gated). CPD/BAT use the same PSU method.

### B3. HV divider → ADC1/2 (needs front-end probing)
The HV sense is a differential amp (ADC1 PB0 ch8 − ADC2 PB1 ch9) behind a high-voltage divider; the
exact low-voltage injection node depends on the front-end circuit (not fully mapped). **First step:**
inject a small DC (≤3.3V, divided) into the HV sense input and watch `HVRAW` move from its offset
floor (~317777 with HV disconnected). Confirm proportionality (HVRAW ∝ injected V). The engineering
scaling (`HV outvol`) needs a valid two-point cal — absent on this clone; a bench two-point cal
(inject known V, record HVRAW) can populate it later. **Do NOT apply real HV in this stage.**

## Stage-1 exit criteria
- [x] Readback MEAS/CAN/NET/STM live on silicon (CDC, no SWD).
- [x] CAN H100/H101/H102 inject → byte-exact parse; engagement guard stays closed.
- [x] Ethernet INJE → v2g_net_rx_ethernet hook (frame accepted, no crash).
- [ ] CP PWM inject → duty/period/state match (B1 — DEFERRED: traced CP node smooths PWM to DC; PD12 unreachable).
- [x] PP analog inject → mV match multimeter + PLUG hysteresis 0↔1 (B2 core, bench-PSU route). CPD/BAT same method, pending.
- [ ] HV low-V inject → HVRAW proportional (B3, front-end node TBD).

Next: Stage 2 (real EVSE, live QCA7005 PLC / SLAC / SDP / TCP / TLS), then Stage 3 (real car, power
drive GATED LAST).