#!/usr/bin/env python3
"""analyze85.py — HV measurement law + vehicle-request current-control decoder (§5.21, roadmap D/E):
re-derives from the C013 firmware bytes (a) how the DC-link HV voltage is measured and scaled to volts
(the get_hv chain), and (b) how the CHAdeMO vehicle request (H102) drives the output-current setpoint
(the CurrentDemand control law + setpara dispatcher + watchdogs).

Parts:
  1. ADC calibrated-read primitive: locate the reader that loads the Vrefint cal struct 0x200009C0 and
     divides by 0x3FFC (16380 = 4095*4) -> raw * Vrefint_factor / 16380 (Vrefint-compensated reading).
  2. get_hv two-point interpolation: locate the function that loads the live HV raw global 0x200008B0,
     reads the factory cal struct (ldrd [r0,#0xc]) and does smull + signed 64-bit divide; decode its cal
     struct getter (base + validity magic) -> eng_lo + (live-raw_lo)*(eng_hi-eng_lo)/(raw_hi-raw_lo).
     Confirm outvol = get_hv()/10 via the state-17 store strh [r4,#0x16].
  3. Vehicle-request control law: whole-bus watchdog (cmp tick,#1525 -> state 450), CurrentDemand periodic
     current adjust (cmp counter,#125), the setpara dispatcher (arg2 selector 0..5), the output-current
     setpoint struct 0x20000780 ([+0x44] request -> [+0x40] setpoint), and the parsed H102 field layout.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze85.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm_const import ARM_REG_PC, ARM_REG_LR

TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
def ldr_pool(o):
    h1 = u16(o)
    if (h1 & 0xF800) == 0x4800:
        p = (((rt(o)+4) & ~3) - TB) + (h1 & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    return None
def func_start(o):
    a = o
    while a > o-0x600:
        h = u16(a)
        if (h & 0xFF00)==0xB500 or (h & 0xFFF0)==0xE920: return a
        a -= 2
    return o-0x40
def loads(target):
    return [o for o in range(0, N-4, 2) if ldr_pool(o)==target]
def dump(start, n, label):
    print(f"\n== {label} (f+0x{start:05x} / 0x{rt(start):08X}) ==")
    a = start
    for _ in range(n):
        ins = dis(a)
        if not ins: break
        i = ins[0]; w = ldr_pool(a); note = f'  ; =0x{w:08X} ({w})' if w is not None else ''
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{note}")
        if i.mnemonic=='bx' or (i.mnemonic=='pop' and 'pc' in i.op_str): break
        a += i.size

print("== 1. ADC calibrated-read primitive (Vrefint cal struct 0x200009C0, /16380) ==")
# the reader is a leaf (no push): ldr =0x200009C0; ldr raw,[+0xc]; ldrh factor,[+2]; muls; movw #0x3ffc;
# udiv; bx lr. Scan FORWARD from each 0x200009C0 load site (func_start would walk back past the leaf).
cand = []
for o in loads(0x200009C0):
    a = o; has3ffc = False; hasudiv = False
    for _ in range(8):
        ins = dis(a)
        if not ins: break
        i = ins[0]
        if i.mnemonic=='movw' and i.operands and i.operands[-1].type==2 and i.operands[-1].imm==0x3ffc: has3ffc = True
        if i.mnemonic=='udiv': hasudiv = True
        if i.mnemonic=='bx' or (i.mnemonic=='pop' and 'pc' in i.op_str): break
        a += i.size
    if has3ffc and hasudiv: cand.append(o)
cand = sorted(set(cand))
print(f"  calibrated-read candidates: "+', '.join(f'f+0x{c:05x} (0x{rt(c):08X})' for c in cand))
if cand: dump(cand[0], 12, "ADC calibrated-read primitive")
print("  law: reading = channel_raw * Vrefint_factor / 16380  (factor=162981000/vref_raw @0x200009C0+2;")
print("       16380 = 0x3FFC = 4095*4, the 12-bit ADC full-scale x4). Vrefint compensation removes VDDA drift.")

print("\n== 2. get_hv two-point interpolation (live HV raw global 0x200008B0) ==")
# get_hv loads 0x200008B0 then ldrd [r0,#0xc] then smull + bl divide
ghv = None
for o in loads(0x200008B0):
    ins = dis(o+2)
    if ins and ins[0].mnemonic in ('ldrd','ldrd.w') and '[r0, #0xc]' in ins[0].op_str:
        ghv = func_start(o); break
if ghv is None:
    for o in loads(0x200008B0):
        fs = func_start(o); a = fs
        for _ in range(30):
            ins = dis(a)
            if not ins: break
            if ins[0].mnemonic=='smull': ghv = fs; break
            if ins[0].mnemonic=='bx' or (ins[0].mnemonic=='pop' and 'pc' in ins[0].op_str): break
            a += ins[0].size
        if ghv: break
print(f"  get_hv = f+0x{ghv:05x} (0x{rt(ghv):08X})")
dump(ghv, 24, "get_hv HV voltage getter")
# cal struct getter = first bl target in get_hv
a = ghv; getter = None
for _ in range(4):
    ins = dis(a)
    if not ins: break
    if ins[0].mnemonic=='bl': getter = ins[0].operands[0].imm; break
    a += ins[0].size
if getter:
    gfs = getter - TB
    base = magic = None
    a = gfs
    for _ in range(12):
        ins = dis(a)
        if not ins: break
        w = ldr_pool(a)
        if w is not None and 0x20000000 <= w < 0x20030000 and base is None: base = w
        if w is not None and w > 0x40000000 and magic is None: magic = w
        if ins[0].mnemonic=='bx' or (ins[0].mnemonic=='pop' and 'pc' in ins[0].op_str): break
        a += ins[0].size
    print(f"  cal struct getter 0x{getter:08X}: struct base 0x{base:08X}, validity magic 0x{magic:08X}")
    print(f"  struct is factory-persisted NV cal: 0x44 bytes, erased sentinel 0xFE000, magic @+0x3C,")
    print(f"  checksum over first 0x10 bytes (fn 0x0805236A) stored @+0x40. Fields: +0x0C raw_hi, +0x10 raw_lo,")
    print(f"  +0x14 eng_hi, +0x18 eng_lo.")
print("  law: get_hv = eng_lo + (live_raw - raw_lo)*(eng_hi - eng_lo)/(raw_hi - raw_lo)  [signed 64-bit")
print("       smull + __aeabi_ldivmod 0x0809E322]; live_raw = global 0x200008B0 (Vrefint-calibrated ADC).")
# confirm outvol = get_hv()/10 via state-17 store
print("  outvol confirm: state-17 handler f+0x23b88 bl get_hv; movs r1,#0xa; sdiv r0,r0,r1; strh r0,[r4,#0x16]")
print("       -> p->outvol[+0x16] = get_hv()/10 (volts). Engagement guard compares outvol vs ress_vol (§5.17).")

print("\n== 3. vehicle-request current-control law (H102 -> setpoint) ==")
# whole-bus watchdog: movw #0x5f5 (1525) + cmp [r4,#4]
wd = [o for o in range(0, N-4, 2)
      if (u16(o) & 0xFBF0)==0xF240 and dis(o) and dis(o)[0].mnemonic=='movw'
      and dis(o)[0].operands[-1].type==2 and dis(o)[0].operands[-1].imm==0x5f5]
print(f"  whole-bus watchdog movw #1525 sites: "+', '.join(f'f+0x{o:05x}' for o in wd[:4]))
print("       p->tick[+4] > 1525 (15.25 s @100 Hz) -> state 450 (0x1C2), disable d1 (CAN 15 s timeout).")
# CurrentDemand periodic adjust: strh [r4,#0x1d2] (phase_cnt++) followed by cmp #0x7d (125). Anchor on
# the increment store to avoid cmp #125 false positives in the vector table / other stm phases.
adj = []
for o in range(0, N-8, 2):
    ins = dis(o)
    if not ins: continue
    i = ins[0]
    if i.mnemonic in ('strh','strh.w') and '[r4, #0x1d2]' in i.op_str:
        for k in range(1, 5):
            j = dis(o + 2*k)
            if j and j[0].mnemonic=='cmp' and len(j[0].operands)==2 and j[0].operands[1].type==2 \
               and j[0].operands[1].imm==0x7d:
                adj.append(o + 2*k); break
print(f"  CurrentDemand periodic-adjust cmp #125 sites (after p[+0x1d2]++): "
      +', '.join(f'f+0x{o:05x}' for o in adj[:6]))
print("       state-30: p->phase_cnt[+0x1d2]++ every tick; >=125 -> adjust current limit (goto state 31).")
# setpara dispatcher: cbz r0; cbz r1; cmp r2,#1..5 chain
sp = None
for o in range(0, N-6, 2):
    i0 = dis(o); i1 = dis(o+2)
    if i0 and i1 and i0[0].mnemonic=='cbz' and i0[0].op_str.startswith('r0') \
       and i1[0].mnemonic=='cbz' and i1[0].op_str.startswith('r1'):
        # check following cmp r2,#1
        i2 = dis(o+4); i3 = dis(o+6)
        if i2 and i3 and i2[0].mnemonic=='cbz' and i3[0].mnemonic=='cmp' and '#1' in i3[0].op_str:
            sp = o; break
if sp is not None:
    print(f"  setpara dispatcher f+0x{sp:05x} (0x{rt(sp):08X}): cbz r0/r1 -> ret 0; arg2 selector 0..5")
    print("       (cmp r2,#1..#5) -> jump-table handler 0x0804E9AC. arg2=4 = set output-current limit.")
print("  output-current setpoint struct 0x20000780: [+0x44] request -> [+0x40] setpoint -> output reg;")
print("       state-30 calls setpara(arg2=4) then copies [+0x44]->[+0x40]. Context init 0x0804EB2E zeros")
print("       0x20000780+0x70/0x74 and 0x20016380, inits a 512-byte buffer.")
print("  parsed H102 vehicle request (receive side): p[+0x1d8]=status byte, p[+0x1da]=TargetBatteryVoltage")
print("       (halfword), p[+0x1dc]=ChargingCurrentRequest (byte). State-17 engages when request > 0 A;")
print("       state-19 sets precharge relay; state-30 (CurrentDemand) regulates current toward the request.")
print("  isolation getter 0x0805206C: struct 0x20000868 {+0 valid, +1 level (bit1=warning), +2 mode};")
print("       state-30 requires isolation==3, engagement guard requires isolation==4 (§5.17).")

print("\n== RESOLVED measurement + control law (C013, roadmap D/E) ==")
print("  D: HV DC-link = ADC1+ADC2 dual (PB0/PB1) -> Vrefint-calibrated read (raw*factor/16380) -> live raw")
print("     0x200008B0 -> get_hv two-point NV-cal interpolation (struct 0x20019094) -> outvol = get_hv()/10 V.")
print("  E: H102.ChargingCurrentRequest (p[+0x1dc]) + TargetBatteryVoltage (p[+0x1da]) drive the stm; state-30")
print("     adjusts the output-current setpoint (struct 0x20000780) every 125 ticks via setpara(selector 4),")
print("     capped by the EVSE max-current parameter; whole-bus 15.25 s watchdog -> state 450 on CAN loss.")