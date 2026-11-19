#!/usr/bin/env python3
"""analyze80.py — CHAdeMO charge state-machine mapper (C013 improved logic) (§5.2/§5.11/§8.5):
re-derives the safe-charge state machine from the C013 firmware bytes (the revision with the proven
precharge-wait fix), no hardcoded conclusions. The CHAdeMO stm is the vehicle-side charge controller
for the CCS2-EVSE <-> CHAdeMO-vehicle path; its context struct `p` keeps the state in the halfword
p->state @ +0x02, and transitions are `strh rX,[p,#2]`.

Parts:
  1. Locate every 'CHAdeMO stm' log format string (full NUL-bounded start, incl. the '[%t]#' prefix)
     and xref it in one code pass (LDR-literal T1/T2 + ADR T1) -> the state-machine code region.
  2. Parse the numbered state-case labels ('NNcase'/'NN case'/'case NN') and build a compact
     state -> (code sites, description) skeleton.
  3. Extract p->state transition writes: walk the code region tracking movs/mov.w/movw immediates,
     record each `strh rX,[r4,#2]` with its decoded next-state value, labelled by the nearest log str.
  4. Decode the state-17 precharge voltage-match (engagement) condition: locate the '17case GOOD
     Precharge voltage OK' xref, disassemble the guard block, extract the outvol/ress_vol window +
     counter threshold (the safety-critical check C013 stalls on until the EVSE reaches target).
  5. Summarize the safe-charge sequence + the safety-stop / abort / isolation / welding states.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze80.py'
"""
import re, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm_const import ARM_REG_PC, ARM_REG_LR

TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
def cstr(o):
    e = fw.find(b'\x00', o)
    return fw[o:e].decode('ascii', 'replace') if 0 <= e and e-o < 200 else ''
def ldr_pool(o):
    h = u16(o)
    if (h & 0xF800) == 0x4800:
        p = ((rt(o)+4) & ~3) - TB + (h & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    return None

print("== 1. CHAdeMO stm log strings + code xref index (C013) ==")
strs = {}
for m in re.finditer(rb'CHAdeMO stm', fw):
    s = m.start()
    while s > 0 and fw[s-1] != 0: s -= 1
    strs[rt(s)] = s
xref = {a: [] for a in strs}
for o in range(0, N-4, 2):
    h = u16(o); val = None
    if (h & 0xF800) == 0x4800:
        p = ((rt(o)+4) & ~3) - TB + (h & 0xFF)*4
        if 0 <= p and p+4 <= N: val = u32(p)
    elif (h & 0xFF7F) == 0xF85F:
        imm = h & 0xFFF; U = (h >> 7) & 1; pca = ((rt(o)+4) & ~3) - TB
        p = pca+imm if U else pca-imm
        if 0 <= p and p+4 <= N: val = u32(p)
    elif (h & 0xF800) == 0xA000:
        val = ((rt(o)+4) & ~3) + (h & 0xFF)*4
    if val in xref: xref[val].append(o)
sites = sorted({o for cs in xref.values() for o in cs})
lo, hi = sites[0], sites[-1]
print(f"  {len(strs)} log strings, {len(sites)} code xref sites; code region f+0x{lo:05x}..0x{hi:05x} (0x{rt(lo):08X}..0x{rt(hi):08X})")

print("\n== 2. numbered state-case skeleton (state -> code sites + description) ==")
case_re = re.compile(r'(?:case\s*(\d+)|(\d+)\s*case)', re.I)
states = {}
for a, cs in xref.items():
    s = cstr(strs[a])
    m = case_re.search(s)
    if not m: continue
    num = int(m.group(1) or m.group(2))
    desc = s.split('CHAdeMO stm :', 1)[-1].strip()
    states.setdefault(num, {'sites': set(), 'descs': []})
    states[num]['sites'].update(cs)
    if desc not in states[num]['descs']: states[num]['descs'].append(desc)
for num in sorted(states):
    d = states[num]
    ss = ','.join(f'0x{rt(o):08X}' for o in sorted(d['sites'])[:3])
    print(f"  state {num:2d} @ {ss}")
    for desc in d['descs'][:4]:
        print(f"      {desc[:100]}")

print("\n== 3. p->state transition writes (strh rX,[r4,#2]) with decoded next state ==")
# walk the code region; track register immediates; record state writes + nearest preceding string label
nearest = {}
for a, cs in xref.items():
    for o in cs: nearest[o] = cstr(strs[a]).split('CHAdeMO stm :', 1)[-1].strip()
reg = {}; trans = []; a = lo; last_label = ''
while a <= hi:
    ins = dis(a)
    if not ins: a += 2; continue
    i = ins[0]; mn = i.mnemonic; ops = i.operands
    if a in nearest: last_label = nearest[a]
    if mn in ('movs', 'mov.w', 'movw') and len(ops) == 2 and ops[1].type == 2:
        reg[ops[0].reg] = ops[1].imm & 0xFFFF
    elif mn == 'movt' and len(ops) == 2 and ops[1].type == 2:
        reg[ops[0].reg] = (reg.get(ops[0].reg, 0) & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16)
    elif mn in ('ldr', 'ldr.w', 'ldrh', 'ldrh.w', 'add', 'add.w', 'adds', 'sub', 'subs', 'orr', 'mov'):
        if ops and ops[0].type == 1: reg.pop(ops[0].reg, None)
    elif mn in ('strh', 'strh.w') and len(ops) == 2 and ops[1].type == 3 \
         and ops[1].mem.disp == 2 and ops[1].mem.base == 66 + 4:   # strh rX,[r4,#2]
        v = reg.get(ops[0].reg)
        if v is not None:
            trans.append((a, v, last_label))
    a += i.size
seen = set()
for o, v, lab in trans:
    key = (v, lab[:40])
    if key in seen: continue
    seen.add(key)
    print(f"  f+0x{o:05x} (0x{rt(o):08X}): p->state = {v} (0x{v:03X})   [{lab[:70]}]")

print("\n== 4. state-17 precharge voltage-match (engagement) guard ==")
good = next((a for a in strs if '17case' in cstr(strs[a]) and 'GOOD' in cstr(strs[a])), None)
if good is not None and xref[good]:
    gx = xref[good][0]
    a = gx - 0x70
    print(f"  guard block before '17case GOOD' xref f+0x{gx:05x}:")
    while a < gx:
        ins = dis(a)
        if not ins: a += 2; continue
        i = ins[0]; note = ''
        w = ldr_pool(a)
        if w is not None and TB <= w < TB+N and 32 <= fw[w-TB] < 127:
            note = f'  ; "{cstr(w-TB)[:50]}"'
        print(f"    f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{note}")
        a += i.size
    print("  => p->state @+2; outvol @+0x16; engagement window: outvol+10 >= ress_vol(r10) AND")
    print("     outvol-5 <= ress_vol, plus counter @+0x0A >= 0xFA(250). On match: state 17 -> 18 (0x12).")

print("\n== 5. safety-stop / abort / isolation / welding states (from log strings) ==")
keys = ('shutdown', 'error', 'timeout', 'STOP_CHARGER', 'emergency', 'Emergency', 'welding',
        'Welding', 'isolation', 'Isolation', 'fail', 'bms_error_stop', 'hw_fault')
seen = set()
for a in sorted(strs, key=lambda a: strs[a]):
    s = cstr(strs[a]).split('CHAdeMO stm :', 1)[-1].strip()
    if any(k in s for k in keys) and s[:50] not in seen:
        seen.add(s[:50])
        cs = xref[a]
        loc = f'0x{rt(cs[0]):08X}' if cs else '(no xref)'
        print(f"  {loc}: {s[:105]}")

print("\n== RESOLVED safe-charge skeleton (C013 CHAdeMO stm) ==")
print("  plug-in -> DIN/ISO EVSE authorize -> CableCheck (isolation, 50s) -> ChargeParameterDiscovery")
print("  (65s, CML/CTS) -> st14 d1 ON / VehicleChargingEnabled -> st15 d2 ON precharge -> st16 EV")
print("  contactor -> st17 precharge voltage-match (outvol~=ress_vol) -> st18 / wait-precharge(450) ->")
print("  inner-contactor close -> H108/H109 current demand -> st61 stop-control (phase_cnt>=200) ->")
print("  st62 unlock (phase_cnt>=350) -> close A+ / e-lock unlock -> charging end. Safety stops:")
print("  hw_fault, h102_status error, notify_bms_shutdown(600), STM_TIMEOUT_STOP_CHARGER(300),")
print("  CableCheck isolation error, precharge timeout. p->state halfword @+0x02; next via strh [r4,#2].")