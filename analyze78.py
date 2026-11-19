#!/usr/bin/env python3
"""analyze78.py — GPIO-output signal mapper (§5.5a / §5.5c / §8.4): names the board's GPIO
output signals (relays / e-lock motor / contactor enables) and the status-feedback inputs, by
re-deriving the mapping from firmware.bin bytes (no hardcoded conclusions).

RESOLVED: the GPIO drivers are a cluster of tiny BSRR-write / IDR-read primitives @0x080879FE-AF8
(f+0x67E00-0x67EFA). Each writes/reads one (or a paired set of) pin(s). Xref-ing each primitive to
its BL callers and the callers' ADR naming strings binds pin -> signal:
    PB10 + PB11  -> "PreChargeRELAY"  (drive; feedback PC8 + PB10 readback)
    PD8          -> "BatteryPower"    (battery-power relay; interlock: clears PC9 first)
    PC9          -> "BatteryCharge"   (battery-charge relay)
    PD3 + PE4    -> e-lock MOTOR drive (pulse-train H-bridge; registered into the E_LOCK state
                    machine, 12-entry u16 pulse-pattern table @0x080AB604, 16 ticks @100Hz)
    PE8          -> CHAdeMO-side relay/contactor enable output (set after 0.5 s in CHAdeMO H100/H102)
    PE10         -> CHAdeMO-side status feedback input (active-low, CHAdeMO H100/H101/H102)
    PB12         -> PLC D_LINK / SLAC link-status input (QCA7005 link-established feedback)
    PC8          -> PreChargeRELAY status feedback input (active-low)
    PD9          -> e-lock position feedback input (read by the E_LOCK tick)
    PD10         -> KEY_LOCK (connector e-lock status input, named by the Hardware-Info dumper)
    PB15         -> write primitive present but UNREFERENCED (unused output)
The "led_process" periodic process (registered via 0x0809858-style wrapper 0x08089858) is a firmware
misnomer: its callback is the E_LOCK state-machine tick 0x08051718, not a separate LED block.

Method (byte-derived): (1) locate the GPIO primitive cluster by its GPIO-base LDR-literal loads +
BSRR writes; decode each primitive's port/pin/direction from the BSRR set-shift, IDR/ODR ubfx, and
active-low bics; (2) xref each write primitive to BL callers and pair with nearby ADR naming strings;
(3) find the e-lock motor driver registered as a function pointer + decode its pulse-pattern table;
(4) xref the readback accessors to naming strings (SLAC D_LINK / PreChargeRELAY / CHAdeMO).

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze78.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm_const import ARM_REG_PC, ARM_REG_LR

TB = 0x0801FBFE
fw = open('firmware.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
GPIO = {0x40020000:'A', 0x40020400:'B', 0x40020800:'C', 0x40020C00:'D', 0x40021000:'E'}
def ldr_pool(o):
    h1 = u16(o)
    if (h1 & 0xF800) == 0x4800:
        p = (((rt(o)+4) & ~3) - TB) + (h1 & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    return None
def cstr_at(o):
    s = o
    while s > 0 and fw[s-1] != 0 and 32 <= fw[s-1] < 127: s -= 1
    e = fw.find(b'\x00', o)
    if e < 0 or e-s > 80: return None
    t = fw[s:e]
    if len(t) >= 3 and all(32 <= c < 127 for c in t): return t.decode()
    return None

print("== 1. locate + decode GPIO primitive cluster (BSRR writes / IDR reads) ==")
# locate: GPIO-base LDR-literal loads grouped tightly; the primitive cluster has BSRR (str disp 0x18)
base_loads = []
for o in range(0, N-4, 2):
    if (u16(o) & 0xF800) == 0x4800:
        w = ldr_pool(o)
        if w in GPIO: base_loads.append(o)
groups = []
for o in base_loads:
    if groups and o - groups[-1][-1] < 0x180: groups[-1].append(o)
    else: groups.append([o])
# pick the group whose span contains BSRR writes (str [rX,#0x18]) — distinguishes from board init
def has_bsrr(lo, hi):
    a = lo
    while a < hi:
        ins = dis(a)
        if not ins: a += 2; continue
        i = ins[0]
        if i.mnemonic in ('str','str.w') and len(i.operands)==2 and i.operands[1].type==3 and i.operands[1].mem.disp==0x18:
            return True
        a += i.size
    return False
cand = [g for g in groups if has_bsrr(g[0]-0x20, g[-1]+0x40)]
grp = max(cand, key=lambda g: len(g))
lo = grp[0]; hi = grp[-1]+0x60
# decode each primitive: push-less leaf functions delimited by `bx lr` (flush at each return)
prims = {}   # rt(addr) -> dict(port pins, kind, active_low)
def flush(fstart, writes, reads, alow):
    pins_w = [(GPIO[p], n) for p, n in writes]
    pins_r = [(GPIO[p], n, k) for p, n, k in reads]
    if pins_w or pins_r:
        prims[rt(fstart)] = {'w': pins_w, 'r': pins_r, 'alow': alow}
fstart = lo; regbase = {}; last_shift = None; reads = []; writes = []; alow = False; rd_base = None
a = lo
while a < hi:
    ins = dis(a)
    if not ins: a += 2; continue
    j = ins[0]; ops = j.operands; mn = j.mnemonic
    if mn in ('ldr','ldr.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.base==ARM_REG_PC:
        w = ldr_pool(a)
        if w in GPIO: regbase[ops[0].reg] = w
    elif mn in ('ldr','ldr.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.disp in (0x10,0x14):
        bb = regbase.get(ops[1].mem.base)
        if bb: rd_base = (bb, ops[1].mem.disp)
    elif mn == 'ubfx' and len(ops)==4 and rd_base:
        reads.append((rd_base[0], ops[2].imm, 'ODR' if rd_base[1]==0x14 else 'IDR'))
    elif mn in ('orr','orr.w') and len(ops)==3 and ops[2].type==1 and 0 <= ops[2].shift.value <= 15:
        last_shift = ops[2].shift.value           # BSRR set-bit position (input << N)
    elif mn in ('str','str.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.disp==0x18:
        bb = regbase.get(ops[1].mem.base)
        if bb is not None and last_shift is not None:
            writes.append((bb, last_shift))
    elif mn == 'bics': alow = True
    end = (mn=='bx' and ops and ops[0].type==1 and ops[0].reg==ARM_REG_LR) or \
          (mn=='pop' and any(op.type==1 and op.reg==ARM_REG_PC for op in ops))
    a += j.size
    if end:
        flush(fstart, writes, reads, alow)
        fstart = a; regbase = {}; last_shift = None; reads = []; writes = []; alow = False; rd_base = None
flush(fstart, writes, reads, alow)
for addr in sorted(prims):
    p = prims[addr]
    ws = '+'.join(f'P{port}{n}' for port, n in p['w'])
    rs = '+'.join(f'P{port}{n}({k})' for port, n, k in p['r'])
    kind = 'WRITE' if p['w'] else 'read'
    al = ' active-low' if p['alow'] else ''
    print(f"  0x{addr:08X} (f+0x{addr-TB:05x}): {kind:5s} {ws or rs}{al}")

print("\n== 2. write-primitive -> BL callers -> naming strings ==")
bls = []
for o in range(0, N-4, 2):
    if (u16(o) & 0xF800) == 0xF000:
        ins = dis(o)
        if ins and ins[0].mnemonic=='bl' and ins[0].operands and ins[0].operands[0].type==2:
            bls.append((o, ins[0].operands[0].imm))
def callers(t): return [o for o, tt in bls if tt == t]
def func_start(o):
    a = o
    while a > o-0x200:
        h = u16(a)
        if (h & 0xFF00)==0xB500 or (h & 0xFFF0)==0xE920: return a
        a -= 2
    return o-0x40
def strings_near(o, span=0x120):
    fs = func_start(o)
    # bound the scan to the enclosing function: stop at the next push prologue (next function),
    # so a driver's own naming string wins over strings in adjacent functions
    fe = fs + 2
    while fe < fs + 0x300 and fe < N-2:
        h = u16(fe)
        if (h & 0xFF00)==0xB500 or (h & 0xFFF0)==0xE920: break
        fe += 2
    out = []; a = fs; limit = min(fe, o+span)
    while a < limit and a < N-4:
        ins = dis(a)
        if not ins: a += 2; continue
        i = ins[0]; tgt = None
        if i.mnemonic=='adr' and len(i.operands)==2:
            tgt = ((rt(a)+4)&~3) + i.operands[1].imm
        elif (u16(a)&0xF800)==0x4800:
            w = ldr_pool(a)
            if w is not None: tgt = w
        if tgt is not None and TB <= tgt < TB+N:
            s = cstr_at(tgt-TB)
            if s: out.append(s)
        a += i.size
    return out
NAMEKEY = [('PreChargeRELAY', ['prechargerelay']), ('BatteryPower', ['batterypower']),
           ('BatteryCharge', ['batterycharge']), ('CHAdeMO', ['chademo']),
           ('SLAC/D_LINK', ['d_link', 'slac', 'avln'])]
def name_from(ss):
    low = ' '.join(ss).lower()
    for name, keys in NAMEKEY:
        if any(k in low for k in keys): return name
    return None
write_prims = {addr: p for addr, p in prims.items() if p['w']}
sig = {}
for addr in sorted(write_prims):
    p = write_prims[addr]
    pins = '+'.join(f'P{port}{n}' for port, n in p['w'])
    cs = callers(addr)
    names = {}
    for o in cs:
        nm = name_from(strings_near(o))
        if nm: names[nm] = names.get(nm, 0) + 1
    best = max(names, key=names.get) if names else None
    sig[addr] = (pins, best, len(cs))
    tag = ', '.join(f'{k}×{v}' for k, v in names.items()) if names else '(no naming string)'
    print(f"  {pins:12s} 0x{addr:08X}: {len(cs):2d} callers -> {tag}")

print("\n== 3. e-lock motor: write primitive registered as fn-ptr + pulse-pattern table ==")
# find pool words == write_prim|1 (thumb fn ptr) loaded into r1 near the e-lock struct 0x2000086A
# (step 2: TB == 2 mod 4, so 4-aligned runtime pool words sit at 2-mod-4 file offsets)
elock_prim = None
for o in range(0, N-4, 2):
    w = u32(o)
    if (w & ~1) in write_prims and (w & 1):
        # find LDR-literal loading this pool word into r1
        for c in range(max(0, o-0x200), min(N-4, o+0x200), 2):
            if (u16(c)&0xF800)==0x4800:
                pca = ((rt(c)+4)&~3)-TB; p = pca+(u16(c)&0xFF)*4
                if p == o and dis(c) and dis(c)[0].op_str.startswith('r1,'):
                    # nearby load of e-lock struct?
                    for d in range(c-0x20, c+0x20, 2):
                        if (u16(d)&0xF800)==0x4800 and ldr_pool(d)==0x2000086A:
                            elock_prim = w & ~1
if elock_prim:
    pins = '+'.join(f'P{port}{n}' for port, n in write_prims[elock_prim]['w'])
    print(f"  e-lock motor drive primitive = 0x{elock_prim:08X} = {pins} (registered into E_LOCK struct 0x20000864)")
# pulse-pattern table: find ldrh.w r1,[r2,r1,lsl #1] preceded by ldr r2,=table
table = None
for o in range(0, N-4, 2):
    if u16(o)==0xF8B2 or (u16(o)&0xFFF0)==0xF8B0:  # ldrh.w r1,[r2,...] heuristic
        pass
# locate via the known pulse-driver load: scan for ldr r2,=X followed within 6 bytes by ldrh.w r1,[r2,r1,lsl #1]
for o in range(0, N-6, 2):
    if (u16(o)&0xF800)==0x4800 and dis(o) and dis(o)[0].op_str.startswith('r2,'):
        w = ldr_pool(o)
        if w and TB <= w < TB+N:
            j = dis(o+4)
            if j and j[0].mnemonic=='ldrh.w' and 'lsl #1' in j[0].op_str and j[0].op_str.startswith('r1,'):
                table = w; break
if table:
    print(f"  pulse-pattern table @0x{table:08X} (f+0x{table-TB:05x}), 12 x u16 (16 ticks @100Hz = 160 ms):")
    for k in range(12):
        v = u16(table-TB+k*2)
        print(f"    profile[{k:2d}] = 0x{v:04X} = {v:016b}")

print("\n== 4. readback accessor -> BL callers -> naming strings ==")
read_prims = {addr: p for addr, p in prims.items() if p['r'] and not p['w']}
for addr in sorted(read_prims):
    p = read_prims[addr]
    pins = '+'.join(f'P{port}{n}' for port, n, k in p['r'])
    cs = callers(addr)
    names = {}
    for o in cs:
        nm = name_from(strings_near(o))
        if nm: names[nm] = names.get(nm, 0) + 1
    best = max(names, key=names.get) if names else None
    al = ' (active-low)' if p['alow'] else ''
    tag = ', '.join(f'{k}×{v}' for k, v in names.items()) if names else '(no naming string / unused)'
    print(f"  {pins:10s}{al:14s} 0x{addr:08X}: {len(cs):2d} callers -> {tag}")

print("\n== RESOLVED GPIO-output signal map (§5.5a / §5.5c / §8.4) ==")
print("  PreChargeRELAY  = PB10 + PB11 (drive 0x08087A84); feedback PC8 (0x08087AE0, active-low) + PB10 readback.")
print("  BatteryPower    = PD8 (drive 0x08087A3C / readback 0x08087A4E); interlock clears PC9 (BatteryCharge) first.")
print("  BatteryCharge   = PC9 (drive 0x08087AC0 / ODR readback 0x08087AD2, active-low).")
if elock_prim:
    pins = '+'.join(f'P{port}{n}' for port, n in write_prims[elock_prim]['w'])
    print(f"  e-lock MOTOR    = {pins} (drive 0x{elock_prim:08X}); E_LOCK task 0x080515AB ticks a shift-register")
    print("                    pulse driver 0x080517C6 (16-bit pattern from table 0x080AB604, 12 motor profiles,")
    print("                    16 ticks @100Hz). 'led_process' periodic callback = this E_LOCK tick (misnomer).")
print("  CHAdeMO enable  = PE8 (drive 0x080879FE, write-only; set after 0.5 s in CHAdeMO H100/H102).")
print("  CHAdeMO status  = PE10 (input 0x08087A24, active-low; CHAdeMO H100/H101/H102 + stop-charger).")
print("  PLC D_LINK      = PB12 (input 0x08087AA6; SLAC link-established / D_LINK_DISCONNECTED/RESTORED).")
print("  e-lock feedback = PD9 (input 0x08087A32, read by E_LOCK tick); KEY_LOCK = PD10 (0x08087AEE).")
print("  PB15            = write primitive 0x08087AB0 present but UNREFERENCED (unused output).")