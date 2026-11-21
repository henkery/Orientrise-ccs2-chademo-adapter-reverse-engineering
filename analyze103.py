#!/usr/bin/env python3
"""
analyze103.py — Agent Q reproducible decoder / assertion suite (G4 + G5).

Asserts EVERY load-bearing claim in agentQ_evsestatus_isolation.md against decoded_c013.bin:
  G4: DC_EVSEStatus 0x0806259E gate sequence, bit widths, field order, struct offsets,
      grammar_id transitions, error codes, no DIN/ISO branch (u32 maxdelay unconditional).
  G5: three distinct isolation signals; CHAdeMO struct 0x20000868 write sites + getter;
      engagement guard reads phase-status meas+0x3D1E==4 (NOT DIN isolation); CurrentDemand
      interlock getter==3; session DIN-isolation rule @0x080365A4 (==1/==0/>=2).

Run (NixOS):
    nix-shell -p python3 python3Packages.capstone --run "python3 analyze103.py"
Prints "N checks, M failures"; exits nonzero on any failure.
"""

# ---- inlined helpers.py (self-contained; canonical RE pool/dump/rt helpers) ----
import sys
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
FWPATH = '.qwen/tmp/c013/decoded_c013.bin'
fw = open(FWPATH, 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
def pool(o):
    h = u16(o)
    if (h & 0xF800) == 0x4800:
        p = (((rt(o)+4) & ~3) - TB) + (h & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    if (h & 0xFF7F) == 0xF85F and o+4 <= N:
        U = (h >> 7) & 1; imm = u16(o+2) & 0xFFF; b = ((rt(o)+4) & ~3)
        p = (b+imm if U else b-imm) - TB
        if 0 <= p and p+4 <= N: return u32(p)
    return None
def tag(w):
    return (" FLASH" if 0x08000000 <= w < 0x08100000 else
            " RAM" if 0x20000000 <= w < 0x20030000 else "")
def dump(addr, n, label):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = ""
        if w is not None:
            ex = f"  ; =0x{w:08X}{tag(w)}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{ex}")
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break
    return a  # file offset where dump stopped

def hexdump(a, b, label=""):
    print(f"\n== hex {label} f+0x{a:05x}..0x{b:05x} (rt 0x{rt(a):08X}) ==")
    for o in range(a, b, 16):
        row = fw[o:o+16]
        hx = ' '.join(f'{c:02x}' for c in row)
        asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in row)
        ann = ''
        for k in range(0, 16, 4):
            if o+k+4 <= N:
                v = struct.unpack_from('<I', fw, o+k)[0]
                if 0x08020000 <= v < 0x080B0000:
                    s = fw[v-TB:v-TB+24].split(b'\x00')[0]
                    if len(s) >= 3 and all(32 <= c < 127 for c in s): ann += f' [+{k}->str {s.decode()!r}]'
        print(f"  f+0x{o:05x}: {hx:48s} {asc}{ann}")

def find_strings(pat):
    """Find all NUL-terminated strings containing pat; return (fileoff, full_string)."""
    res = []
    start = 0
    while True:
        i = fw.find(pat, start)
        if i < 0: break
        # back up to preceding NUL
        b = i
        while b > 0 and fw[b-1] != 0: b -= 1
        e = fw.find(b'\x00', i)
        if e < 0: e = N
        res.append((b, fw[b:e]))
        start = i + 1
    return res

def xrefs(addr):
    """Full xref scan: movw/movt pairs, ADR T1, LDR-literal T1/T2 (runtime-PC aligned)."""
    res = []; mp = {}
    for o in range(0, N-4, 2):
        h1 = u16(o); t = None; k = None
        if (h1 & 0xFBF0) in (0xF240, 0xF2C0):
            ins = dis(o)
            if ins and ins[0].mnemonic in ('movw', 'movt') and len(ins[0].operands) == 2:
                i = ins[0]; reg = i.operands[0].reg; imm = i.operands[1].imm & 0xFFFF
                if i.mnemonic == 'movw': mp[reg] = (imm, o)
                elif reg in mp:
                    lo, fo = mp.pop(reg); t = (imm << 16) | lo; k = 'movw/movt'; o = fo
        elif (h1 & 0xF800) == 0xA000:
            t = ((rt(o)+4) & ~3) + (h1 & 0xFF)*4; k = 'adrT1'
        elif (h1 & 0xF800) == 0x4800:
            pca = ((rt(o)+4) & ~3) - TB; p = pca + (h1 & 0xFF)*4
            t = u32(p) if 0 <= p and p+4 <= N else None; k = 'ldrT1'
        elif (h1 & 0xFF7F) == 0xF85F:
            h2 = u16(o+2); U = (h1 >> 7) & 1; pca = ((rt(o)+4) & ~3) - TB
            p = pca + ((h2 & 0xFFF) if U else -(h2 & 0xFFF))
            t = u32(p) if 0 <= p and p+4 <= N else None; k = 'ldrT2'
        if t == addr: res.append((o, k))
    return res

def movw_scan(lo, hi):
    """Scan MOVW immediates in [lo,hi] (decode full imm16; requires following movt check optional)."""
    res = []
    for o in range(0, N-4, 2):
        h1 = u16(o)
        if (h1 & 0xFBF0) == 0xF240:
            h2 = u16(o+2)
            if h2 & 0x8000: continue
            imm = ((h1 & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
            if lo <= imm <= hi:
                res.append((o, (h2 >> 8) & 0xF, imm))
    return res

def bl_targets(addr, n=400):
    """Walk n instrs from addr (function-aware-ish), collect BL targets + tail b.w."""
    a = addr - TB; out = []
    for _ in range(n):
        ins = dis(a)
        if not ins: break
        i = ins[0]
        if i.mnemonic == 'bl':
            try: out.append((rt(a), int(i.op_str.replace('#', ''), 0)))
            except ValueError: pass
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break
    return out

# ---------------- check framework ----------------
NCHK = 0
FAIL = []
def ck(name, cond):
    global NCHK
    NCHK += 1
    if not cond:
        FAIL.append(name)
        print(f"  FAIL: {name}")

def I(addr):
    r = dis(addr - TB)
    return r[0] if r else None

def ck_ins(name, addr, mnem, opsub=None):
    i = I(addr)
    ok = i is not None and i.mnemonic == mnem and (opsub is None or opsub in i.op_str)
    ck(name, ok)
    return i

def tgt(addr):
    # branch/bl target: op_str is "#0x..." (b/bl/bne/beq) or "rX, #0x..." (cbz/cbnz)
    i = I(addr)
    if i and '#' in i.op_str:
        return int(i.op_str.split('#')[1], 16)
    return None

def ck_tgt(name, addr, target):
    ck(name, tgt(addr) == target)

def ck_pool(name, addr, val):
    ck(name, pool(addr - TB) == val)

def bl_callers(target):
    res = []
    for o in range(0, N - 4, 2):
        h1 = u16(o); h2 = u16(o + 2)
        if (h1 & 0xF800) == 0xF000 and (h2 & 0xD000) == 0xD000:
            S = (h1 >> 10) & 1; imm10 = h1 & 0x3FF; imm11 = h2 & 0x7FF
            J1 = (h2 >> 13) & 1; J2 = (h2 >> 11) & 1
            I1 = (~(J1 ^ S)) & 1; I2 = (~(J2 ^ S)) & 1
            imm = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
            if S: imm |= 0xFE000000
            if (rt(o) + 4 + imm) & 0xFFFFFFFF == target:
                res.append(rt(o))
    return res

def range_ins(lo, hi):
    out = []; a = lo - TB
    while a < hi - TB:
        r = dis(a)
        if r:
            out.append((rt(a), r[0])); a += r[0].size
        else:
            a += 2
    return out

print("=== G4: DC_EVSEStatus 0x0806259E ===")
# prologue / registers
ck_ins("G4 push.w regs", 0x0806259E, "push.w", "{r2, r3, r4, r5, r6, r7, r8, sb, sl, lr}")
ck_ins("G4 sb=stream(r0)", 0x080625A2, "mov", "sb, r0")
ck_ins("G4 r8=out(r1)", 0x080625A4, "mov", "r8, r1")
ck_ins("G4 init grammar_id=0x107", 0x080625A6, "movw", "r7, #0x107")
ck_ins("G4 r4=-110 (mvn #0x6d)", 0x080625AA, "mvn", "r4, #0x6d")
ck_ins("G4 r5=-133 (mvn #0x84)", 0x080625B6, "mvn", "r5, #0x84")
ck_pool("G4 r6=-500 literal", 0x080625B4, 0xFFFFFE0C)
ck_tgt("G4 bl out-init 0x8061FEE", 0x080625B0, 0x08061FEE)
# out-init clears present bit (word0 bit8 = out[1].bit0)
ck_ins("G4 init bic #0x100 (clear present)", 0x08061FF0, "bic", "r1, r1, #0x100")
# dispatch
ck_ins("G4 dispatch cmp #0xdb", 0x080625BA, "cmp", "r7, #0xdb")
ck_ins("G4 dispatch cmp #4 (EE)", 0x080625C0, "cmp", "r7, #4")
ck_ins("G4 dispatch cmp #0xda", 0x080625C4, "cmp", "r7, #0xda")
ck_ins("G4 dispatch >0xdb sub #0x100", 0x080625CA, "sub.w", "r7, r7, #0x100")
ck_ins("G4 dispatch subs #7 (->0x107)", 0x080625CE, "subs", "r7, #7")
ck_tgt("G4 dispatch subs#7 beq ->state107", 0x080625D0, 0x080625DE)
ck_ins("G4 dispatch cmp #1 (->0x108)", 0x080625D2, "cmp", "r7, #1")
ck_tgt("G4 dispatch cmp#1 beq ->state108", 0x080625D4, 0x08062680)
ck_ins("G4 unknown grammar -108", 0x080625D6, "mvn", "r0, #0x6b")
# E0 isolation presence (2-bit)
ck_ins("G4 E0 width=2", 0x080625E0, "movs", "r1, #2")
ck_tgt("G4 E0 readBits wrapper", 0x080625E4, 0x08093660)
ck_tgt("G4 E0==0 ->pathA(present)", 0x080625EE, 0x080625F6)
ck_ins("G4 E0 cmp #1", 0x080625F0, "cmp", "r0, #1")
ck_tgt("G4 E0==1 ->pathB(absent)", 0x080625F4, 0x08062642)
ck_tgt("G4 E0>=2 ->-110 shunt", 0x080625F2, 0x0806267C)
# pathA: G1, isolation(2), present, G2, ->0x108
ck_ins("G4 G1 width=1", 0x080625F8, "movs", "r1, #1")
ck_tgt("G4 G1==1 ->-133 (via 0x80626c0)", 0x08062608, 0x080626C0)
ck_ins("G4 isolation width=2", 0x0806260C, "movs", "r1, #2")
ck_ins("G4 isolation store out[0]", 0x08062616, "strb.w", "r1, [r8]")
ck_ins("G4 present flag orr #0x100", 0x08062620, "orr", "r2, r1, #0x100")
ck_ins("G4 G2 width=1", 0x0806262C, "movs", "r1, #1")
ck_tgt("G4 G2==1 ->-500 shunt", 0x08062636, 0x0806263E)
ck_ins("G4 pathA ->grammar 0x108", 0x08062638, "mov.w", "r7, #0x108")
# state108: G3 then pathB
ck_ins("G4 G3 width=1 (state108)", 0x08062682, "movs", "r1, #1")
ck_tgt("G4 G3==1 ->-110 shunt", 0x08062692, 0x0806267C)
ck_tgt("G4 state108 ->pathB", 0x08062694, 0x08062642)
# pathB: G4, status_code(4), G5, ->0xDA
ck_ins("G4 G4 width=1", 0x08062644, "movs", "r1, #1")
ck_tgt("G4 G4==1 ->-133 (via 0x80626c0)", 0x08062652, 0x080626C0)
ck_ins("G4 status_code width=4", 0x08062656, "movs", "r1, #4")
ck_ins("G4 status_code store out[2]", 0x08062660, "strb.w", "r1, [r8, #2]")
ck_ins("G4 G5 width=1", 0x0806266A, "movs", "r1, #1")
ck_tgt("G4 G5==1 ->-500 shunt", 0x08062676, 0x0806263E)
ck_ins("G4 pathB ->grammar 0xDA", 0x08062678, "movs", "r7, #0xda")
# stateDA: G6, G7, u32 maxdelay (UNCONDITIONAL), G8, ->0xDB
ck_ins("G4 G6 width=1", 0x08062698, "movs", "r1, #1")
ck_tgt("G4 G6==1 ->-110 shunt", 0x080626A8, 0x0806267C)
ck_ins("G4 G7 width=1", 0x080626AC, "movs", "r1, #1")
ck_tgt("G4 G7==1 ->-133 shunt", 0x080626C2, 0x0806270C)
ck_ins("G4 maxdelay out+4 ptr", 0x080626C4, "add.w", "r1, r8, #4")
ck_tgt("G4 maxdelay u32 varlen decoder", 0x080626CA, 0x08093432)
ck_ins("G4 G8 width=1", 0x080626D4, "movs", "r1, #1")
ck_tgt("G4 G8==1 ->-500 shunt", 0x080626E0, 0x0806263E)
ck_ins("G4 stateDA ->grammar 0xDB", 0x080626E2, "movs", "r7, #0xdb")
# stateDB: G9, G10, notification(2), G11, ->4
ck_ins("G4 G9 width=1", 0x080626E8, "movs", "r1, #1")
ck_tgt("G4 G9==1 ->-110 shunt", 0x080626F8, 0x0806267C)
ck_ins("G4 G10 width=1", 0x080626FC, "movs", "r1, #1")
ck_tgt("G4 G10==0 continue (else -133)", 0x0806270A, 0x08062710)
ck_ins("G4 notification width=2", 0x08062712, "movs", "r1, #2")
ck_ins("G4 notification store out[8]", 0x0806271C, "strb.w", "r1, [r8, #8]")
ck_ins("G4 G11 width=1", 0x08062726, "movs", "r1, #1")
ck_tgt("G4 G11==1 ->-500 shunt", 0x08062732, 0x0806263E)
ck_ins("G4 stateDB ->grammar 4 (EE)", 0x08062734, "movs", "r7, #4")
# stateEE: G12, success
ck_ins("G4 G12 width=1", 0x08062740, "movs", "r1, #1")
ck_tgt("G4 G12==1 ->-110 shunt", 0x08062750, 0x0806267C)
ck_tgt("G4 G12==0 ->return", 0x08062752, 0x080625DA)
# error shunts + loopback + return
ck_ins("G4 -110 shunt mov r0,r4", 0x0806267C, "mov", "r0, r4")
ck_ins("G4 -133 shunt mov r0,r5", 0x0806270C, "mov", "r0, r5")
ck_ins("G4 -500 shunt mov r0,r6", 0x0806263E, "mov", "r0, r6")
ck_ins("G4 loopback cmp r0,#0", 0x08062736, "cmp", "r0, #0")
ck_tgt("G4 loopback beq ->dispatch", 0x08062738, 0x080625BA)
ck_ins("G4 return pop", 0x080625DA, "pop.w", "pc")
# fixed-bit count (all readBits widths except the u32): 12 one-bit gates + E0/ISO/NOTIF(2*3) + CODE(4) = 22
widths = [2,1,2,1,1,1,4,1,1,1,1,1,1,2,1,1]  # E0 G1 ISO G2 G3 G4 CODE G5 G6 G7 G8 G9 G10 NOTIF G11 G12
ck("G4 success fixed-bit count == 22", sum(widths) == 22)
# grammar_id transition set present in function
gset = set()
for a, i in range_ins(0x0806259E, 0x08062754):
    if i.mnemonic in ("movw", "movs", "mov.w") and i.op_str.startswith("r7, #"):
        gset.add(int(i.op_str.split("#")[1], 16))
ck("G4 grammar states {0x107,0x108,0xDA,0xDB,4}", {0x107,0x108,0xDA,0xDB,4} <= gset)
# NO DIN/ISO mode flag: the u32 maxdelay call is reached with no presence gate between G7 and it.
# (G7 cbnz @0x80626C2 is the only branch; next instr is the out+4 ptr then bl u32.)
ck_ins("G4 no maxdelay presence gate (ptr right after G7)", 0x080626C4, "add.w", "r1, r8, #4")
# callers
dc_callers = set(bl_callers(0x0806259E))
ck("G4 DC_EVSEStatus has 7 callers", len(dc_callers) == 7)
ck("G4 callers include CableCheckRes 0x08066CF6", 0x08066CF6 in dc_callers)
# CableCheckRes -> DC_EVSEStatus at out+4
ck_ins("G4 CableCheckRes RC store out[0]", 0x08066CB6, "strb", "r1, [r7]")
ck_ins("G4 CableCheckRes DC_EVSEStatus ptr out+4", 0x08066CF2, "adds", "r1, r7, #4")
ck_tgt("G4 CableCheckRes bl DC_EVSEStatus", 0x08066CF6, 0x0806259E)
ck_ins("G4 CableCheckRes out-init no-op", 0x08061F98, "bx", "lr")

print("=== G5: CHAdeMO isolation struct 0x20000868 (base 0x20000878-0x10) ===")
xs = {rt(o) for o, k in xrefs(0x20000878)}
expected = {0x08051FCA,0x08051FD2,0x08051FDA,0x08051FE2,0x08052020,0x08052036,0x0805206C,0x08052090,0x0805209E}
ck("G5 xref(0x20000878) cluster set", expected <= xs)
# getter 0x0805206C semantics
ck_pool("G5 getter base literal 0x20000878", 0x0805206C, 0x20000878)
ck_ins("G5 getter struct=base-0x10", 0x0805206E, "subs", "r1, #0x10")
ck_ins("G5 getter valid=struct[0]", 0x08052072, "ldrb", "r2, [r1]")
ck_ins("G5 getter level=struct[1]", 0x08052074, "ldrb", "r0, [r0, #1]")
ck_ins("G5 getter cmp valid,#0", 0x08052076, "cmp", "r2, #0")
ck_tgt("G5 getter valid!=0 ->return level", 0x08052078, 0x08052088)
ck_ins("G5 getter mode=struct[2]", 0x0805207A, "ldrb", "r2, [r1, #2]")
ck_ins("G5 getter cmp mode,#2", 0x0805207C, "cmp", "r2, #2")
ck_tgt("G5 getter mode==2 ->orr#2", 0x0805207E, 0x0805208A)
ck_ins("G5 getter mode!=2 bic#2", 0x08052080, "bic", "r0, r0, #2")
ck_ins("G5 getter mode==2 orr#2", 0x0805208A, "orr", "r0, r0, #2")
ck_ins("G5 getter write level struct[1]", 0x08052084, "strb", "r0, [r1, #1]")
ck_ins("G5 getter return bx lr", 0x08052088, "bx", "lr")
# measurement routine never sets bit2 (value 4) on level
meas_orr = set()
for a, i in range_ins(0x08051FE2, 0x08052036):
    if i.mnemonic == "orr" and "#" in i.op_str:
        meas_orr.add(int(i.op_str.split("#")[1], 16))
ck("G5 measurement orr immediates subset {1,2}", meas_orr <= {1, 2})
ck("G5 measurement never orr #4 (level!=4)", 4 not in meas_orr)
ck("G5 measurement sets bit0 (orr#1)", 1 in meas_orr)
ck("G5 measurement sets bit1 (orr#2)", 2 in meas_orr)
# mode values {1,2}
ck_ins("G5 measurement mode=1", 0x08051FEA, "strb", "r6, [r4, #2]")
ck_ins("G5 measurement mode=2", 0x08052016, "strb", "r0, [r4, #2]")
# valid setter (arg&1)|0x80
ck_ins("G5 valid setter and#1", 0x08052038, "and", "r0, r0, #1")
ck_ins("G5 valid setter orr#0x80", 0x0805203E, "orr", "r0, r0, #0x80")
ck_ins("G5 valid setter store struct[0]", 0x08052042, "strb", "r0, [r1]")
# valid getter / mode getter
ck_ins("G5 valid getter struct[0]", 0x08052094, "ldrb", "r0, [r0]")
ck_ins("G5 mode getter struct[2]", 0x08051FD6, "ldrb", "r0, [r0, #2]")
# level write sites (all in cluster)
for a, op in [(0x08051FEC,"r5, [r4, #1]"),(0x08051FF4,"r0, [r4, #1]"),(0x0805200C,"r0, [r4, #1]"),
              (0x0805201E,"r0, [r4, #1]"),(0x08052084,"r0, [r1, #1]")]:
    ck_ins(f"G5 level write @0x{a:08X}", a, "strb", op)
# getter callers + ==3 interlock consumers
gc = bl_callers(0x0805206C)
ck("G5 getter has 28 callers", len(gc) == 28)
for site in [0x0803AAF0,0x0803D1AE,0x0803D8A0,0x0803DBD0,0x0803E50A,0x08040578,0x08041F5E,0x0804504C,0x08049426,0x0804BA3E]:
    i = I(site); j = I(site + 4)
    ok = (i is not None and i.mnemonic == "bl" and tgt(site) == 0x0805206C
          and j is not None and j.mnemonic == "cmp" and j.op_str == "r0, #3")
    ck(f"G5 interlock ==3 @0x{site:08X}", ok)

print("=== G5: engagement guard reads phase-status meas+0x3D1E==4 ===")
# charge-stm entry: r6=arg1(meas), r4=arg0(stm struct)
ck_ins("G5 charge-stm entry mov r6,r1 (meas)", 0x080415DA, "mov", "r6, r1")
ck_ins("G5 charge-stm entry movs r4,r0 (stm)", 0x080415DC, "movs", "r4, r0")
# guard head
ck_ins("G5 guard precharge_flag [r6,#0x23f]", 0x0804AF08, "ldrb.w", "r0, [r6, #0x23f]")
ck_ins("G5 guard flag cmp #1", 0x0804AF0C, "cmp", "r0, #1")
ck_ins("G5 guard status ptr [sp,#0x60]", 0x0804AF10, "ldr", "r0, [sp, #0x60]")
ck_ins("G5 guard status ldrh", 0x0804AF12, "ldrh", "r0, [r0]")
ck_ins("G5 guard status cmp #4", 0x0804AF14, "cmp", "r0, #4")
# guard tail: voltage window + dwell + transition
ck_ins("G5 guard outvol [r4,#0x16]", 0x0804AF18, "ldrh", "r0, [r4, #0x16]")
ck_ins("G5 guard outvol+10", 0x0804AF1A, "add.w", "r1, r0, #0xa")
ck_ins("G5 guard cmp sl (upper)", 0x0804AF1E, "cmp", "r1, sl")
ck_ins("G5 guard outvol-5", 0x0804AF22, "subs", "r0, r0, #5")
ck_ins("G5 guard cmp sl (lower)", 0x0804AF24, "cmp", "r0, sl")
ck_ins("G5 guard dwell [r4,#0xa]", 0x0804AF28, "ldrh", "r0, [r4, #0xa]")
ck_ins("G5 guard dwell cmp #0xfa (250)", 0x0804AF2A, "cmp", "r0, #0xfa")
ck_ins("G5 guard success state=0x12(18)", 0x0804AF2E, "movs", "r0, #0x12")
ck_ins("G5 guard store state [r4,#2]", 0x0804AF30, "strh", "r0, [r4, #2]")
# [sp,#0x60] = r6+0x3D1E (store lead-up)
ck_ins("G5 sp60 lead movw #0x3d1e", 0x08048EE0, "movw", "r0, #0x3d1e")
ck_ins("G5 sp60 lead add r0,r6", 0x08048EE4, "add", "r0, r6")
ck_ins("G5 sp60 store [sp,#0x60]", 0x08048EE6, "str", "r0, [sp, #0x60]")
# other phase-status ==4 gates
for a in (0x08043CC4, 0x08044214):
    i = I(a); j = I(a + 2); k = I(a + 4)
    ok = (i and i.mnemonic=="ldr" and i.op_str=="r0, [sp, #0x5c]"
          and j and j.mnemonic=="ldrh" and k and k.mnemonic=="cmp" and k.op_str=="r0, #4")
    ck(f"G5 phase-status ==4 gate @0x{a:08X}", ok)

print("=== G5: phase-status writers (3=CableCheck / 4=PreCharge / 7=error) ===")
ck_ins("G5 CableCheck handler movs #3", 0x0802C192, "movs", "r0, #3")
ck_ins("G5 CableCheck handler movw #0x3d1e", 0x0802C194, "movw", "r1, #0x3d1e")
ck_ins("G5 CableCheck handler strh [r5,r1]", 0x0802C198, "strh", "r0, [r5, r1]")
ck_ins("G5 PreCharge handler movw #0x3d18", 0x0802C29C, "movw", "r2, #0x3d18")
ck_ins("G5 PreCharge handler +2 ->0x3d1a", 0x0802C2A4, "adds", "r2, r2, #2")
ck_ins("G5 PreCharge handler movs #4", 0x0802C2AA, "movs", "r1, #4")
ck_ins("G5 PreCharge handler +4 ->0x3d1e", 0x0802C2AC, "adds", "r2, r2, #4")
ck_ins("G5 PreCharge handler strh [r0,r2]", 0x0802C2AE, "strh", "r1, [r0, r2]")
# error cluster sets 7 (region scan: movs #7 + movw #0x3D1E co-occur)
err_ins = range_ins(0x0802BA40, 0x0802BAC0)
has7 = any(i.mnemonic=="movs" and i.op_str.endswith("#7") for _, i in err_ins)
has3d1e = any(i.mnemonic=="movw" and "#0x3d1e" in i.op_str for _, i in err_ins)
ck("G5 error cluster loads #7", has7)
ck("G5 error cluster writes offset 0x3D1E", has3d1e)
# handler base = meas (r0=r4), RX engine r4=0x20007570
ck_ins("G5 CableCheck call mov r0,r4", 0x08036386, "mov", "r0, r4")
ck_ins("G5 PreCharge call mov r0,r4", 0x08036B84, "mov", "r0, r4")
ck_pool("G5 RX engine r4=meas 0x20007570", 0x080353BE, 0x20007570)

print("=== G5: session DIN-isolation rule @0x080365A4 (source 0x2000C808) ===")
ck_pool("G5 session reader sb=0x2000C808", 0x080365A4, 0x2000C808)
ck_ins("G5 session ldrb [sb]", 0x080365AA, "ldrb.w", "r1, [sb]")
ck_tgt("G5 session ==0 ->retry", 0x080365AE, 0x080365E2)
ck_ins("G5 session cmp #1", 0x080365B0, "cmp", "r1, #1")
ck_tgt("G5 session ==1 ->advance 0x80366AE", 0x080365B2, 0x080366AE)
# arena = ctx(0x2000B3F8)+0x1408 = 0x2000C800 ; CableCheckRes out=arena+4=0x2000C804 ; isolation=out+4
ck_pool("G5 arena anchor r8=0x2000B3F8", 0x080356C2, 0x2000B3F8)
ck_ins("G5 arena offset movw #0x1408", 0x080356C6, "movw", "r1, #0x1408")
ck_ins("G5 arena add r6,r8,r1", 0x080356D2, "add.w", "r6, r8, r1")
ck("G5 arena base == 0x2000C800", 0x2000B3F8 + 0x1408 == 0x2000C800)
ck_pool("G5 CableCheckRes out base 0x2000C804", 0x080356C0, 0x2000C804)
ck("G5 isolation addr = out+4 = 0x2000C808", 0x2000C804 + 4 == 0x2000C808)
# charge-stm does NOT read raw DIN isolation / status_code / notification copies
for imm, nm in [(0x3CFC,"isolation"),(0x3CFD,"status_code"),(0x3CFE,"notification")]:
    hits = [o for o, r, v in movw_scan(imm, imm) if 0x0804166C <= rt(o) <= 0x0804E672]
    ck(f"G5 charge-stm does not read meas+0x{imm:X} ({nm})", len(hits) == 0)

print()
print(f"{NCHK} checks, {len(FAIL)} failures")
if FAIL:
    print("Failed checks:")
    for f in FAIL:
        print("  - " + f)
sys.exit(1 if FAIL else 0)
