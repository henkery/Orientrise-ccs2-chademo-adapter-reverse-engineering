#!/usr/bin/env python3
"""analyze101.py — Agent O assertion script (G1+G2, C013 DIN Req EXI encoder).

Asserts EVERY load-bearing claim in agentO_exi_req_encode.md against the firmware bytes,
using python3 + capstone (helpers inlined). Two independent evidence paths:
  (a) encoder root 0x0806FA9C flag-bit dispatch -> 7-bit event -> production;
  (b) session-SM Req builders set name-word bit + W40 DIN gate -> ev03 dispatcher choice.
Plus a decoder tbb (0x080699BC) flag cross-check (encoder ev == decoder ev).

Run:
    nix-shell -p python3 python3Packages.capstone --run "python3 analyze101.py"
Prints "N checks, 0 failures"; exits nonzero on any failure.
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

# ---- capstone reg ids (ARM) ----
R0, R1, R2, R3, R4, R5, R6, R7, R8 = 66, 67, 68, 69, 70, 71, 72, 73, 74

checks = 0
failures = 0
def ck(cond, msg):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1
        print(f"  FAIL: {msg}")

def I(addr):
    ins = dis(addr - TB)
    if not ins:
        raise RuntimeError(f"no instruction @ 0x{addr:08X}")
    return ins[0]

def mn(addr):  return I(addr).mnemonic
def ops(addr): return I(addr).op_str
def imm(addr, idx=-1):
    o = I(addr).operands[idx]
    return o.imm & 0xFFFFFFFF if o.type == 2 else None
def dest(addr):
    o = I(addr).operands[0]
    return o.reg if o.type == 1 else None
def memdisp(addr, idx=1):
    o = I(addr).operands[idx]
    return o.mem.disp if o.type == 3 else None
def membase(addr, idx=1):
    o = I(addr).operands[idx]
    return o.mem.base if o.type == 3 else None
def bl(addr):
    i = I(addr)
    return i.operands[0].imm & 0xFFFFFFFF if i.operands and i.operands[0].type == 2 else None
def is_mn(addr, *names): return mn(addr).split('.')[0] in names

print("== Agent O — DIN Req EXI encoder assertions (C013) ==")

# ---------------------------------------------------------------------------
# GROUP A — encoder root 0x0806FA9C prologue: leading 0x80 + W40/W44/W48 loads
# ---------------------------------------------------------------------------
print("[A] encoder root prologue")
ck(is_mn(0x0806FA9C, 'push'), "root push")
ck(mn(0x0806FA9E) == 'mov' and ops(0x0806FA9E) == 'r4, r1', "root mov r4,r1 (doc)")
ck(mn(0x0806FAA0) == 'mov' and ops(0x0806FAA0) == 'r5, r0', "root mov r5,r0 (stream)")
ck(bl(0x0806FAA2) == 0x08093C92, "root bl TX leading-0x80 0x08093C92")
ck(is_mn(0x0806FAAA, 'add') and imm(0x0806FAAA) == 0x4000 and dest(0x0806FAAA) == R2,
   "root add r2,r4,#0x4000")
ck(is_mn(0x0806FAAE, 'ldr') and memdisp(0x0806FAAE) == 0x140 and membase(0x0806FAAE) == R2
   and dest(0x0806FAAE) == R1, "root ldr r1,[r2,#0x140] = W40")
ck(is_mn(0x0806FACE, 'ldr') and memdisp(0x0806FACE) == 0x144, "root ldr W44 [r2,#0x144]")
ck(is_mn(0x0806FBD0, 'ldr') and memdisp(0x0806FBD0) == 0x148, "root ldr W48 [r2,#0x148]")

# ---------------------------------------------------------------------------
# GROUP B — W40 bit1 arm -> root event 0x4D -> ev4d 0x080706F6
# ---------------------------------------------------------------------------
print("[B] W40 bit1 -> root event 0x4D")
ck(mn(0x08070362) == 'lsls' and imm(0x08070362) == 0x1e and dest(0x08070362) == R2,
   "lsls r2,r1,#0x1e (test W40 bit1)")
ck(is_mn(0x08070364, 'bpl') and bl(0x08070364) == 0x0807037E, "bpl skip 0x0807037E")
ck(mn(0x08070366) == 'movs' and imm(0x08070366) == 0x4d and dest(0x08070366) == R2,
   "movs r2,#0x4d  <<< ROOT EVENT 0x4D")
ck(mn(0x08070368) == 'movs' and imm(0x08070368) == 7, "movs r1,#7 (7-bit event)")
ck(bl(0x0807036C) == 0x08093AE4, "bl writeBits wrapper 0x08093AE4")
ck(mn(0x08070374) == 'mov' and ops(0x08070374) == 'r1, r4', "mov r1,r4 (doc)")
ck(bl(0x08070378) == 0x080706F6, "bl ev4d production 0x080706F6")

# ---------------------------------------------------------------------------
# GROUP C — ev4d 0x080706F6: DIN header sub + add #0x1400 body base + ev03
# ---------------------------------------------------------------------------
print("[C] ev4d body-base resolution")
ck(bl(0x0807070A) == 0x0806F8FC, "ev4d bl DIN header sub 0x0806F8FC")
ck(is_mn(0x0807071E, 'add') and imm(0x0807071E) == 0x1400 and dest(0x0807071E) == R1
   and ops(0x0807071E).startswith('r1, r4'), "ev4d add.w r1,r4,#0x1400 (body base)")
ck(bl(0x08070724) == 0x0806D6D2, "ev4d bl ev03 dispatcher 0x0806D6D2")

# ---------------------------------------------------------------------------
# GROUP D — ev03 dispatcher 0x0806D6D2 name-word reads
# ---------------------------------------------------------------------------
print("[D] ev03 name-word reads")
ck(mn(0x0806D6D6) == 'movw' and imm(0x0806D6D6) == 0x2d38, "movw #0x2d38 (name-A offset)")
ck(is_mn(0x0806D6DC, 'ldr') and '[r1, r0]' in ops(0x0806D6DC), "ldr name-A [r1,r0]")
ck(mn(0x0806D866) == 'movw' and imm(0x0806D866) == 0x2d3c, "movw #0x2d3c (name-B offset)")
ck(is_mn(0x0806D86A, 'ldr') and '[r5, r1]' in ops(0x0806D86A), "ldr name-B [r5,r1]")

# ---------------------------------------------------------------------------
# GROUP E — nine choice arms: test bit -> 6-bit choice -> sub-production bl
# ---------------------------------------------------------------------------
print("[E] ev03 nine choice arms")
# (name, test_addr, shift_or_None(cmp), choice, sub_addr, bl_sub_addr)
ARMS = [
    ("SessionSetup",     0x0806DA06, 0x1e, 0x1D, 0x0806ABEA, 0x0806DA1A),
    ("ServiceDiscovery", 0x0806D99E, 0x1c, 0x19, 0x0806B06A, 0x0806D9B2),
    ("CPD",              0x0806D7A2, 0x12, 0x07, 0x0806CEF0, 0x0806D7B8),
    ("CableCheck",       0x0806D6FA, 0x04, 0x01, 0x0806D698, 0x0806D710),
    ("PreCharge",        0x0806D930, 0x02, 0x15, 0x0806B4DE, 0x0806D946),
    ("PowerDelivery",    0x0806D8F8, 0x10, 0x13, 0x0806B814, 0x0806D90E),
    ("CurrentDemand",    0x0806D84A, None, 0x0D, 0x0806BDDC, 0x0806D860),
    ("Welding",          0x0806DA6E, 0x1e, 0x21, 0x0806AA92, 0x0806DA82),
    ("SessionStop",      0x0806DA3A, 0x0a, 0x1F, 0x0806AB0E, 0x0806DA4E),
]
for name, ta, shift, choice, sub, blsub in ARMS:
    if shift is None:  # CurrentDemand uses cmp r0,#0 / bge (bit31)
        ck(mn(ta) == 'cmp' and imm(ta) == 0, f"{name}: cmp r0,#0 (bit31 test)")
    else:
        ck(mn(ta) == 'lsls' and imm(ta) == shift, f"{name}: lsls #{shift:#x} (name bit {31-shift})")
    # scan window test_addr..bl_sub for movs r2,#choice + movs r1,#6 + bl writeBits
    a = ta; got_choice = False; got_6bit = False; got_wb = False
    while a <= blsub:
        i = I(a)
        if i.mnemonic == 'movs' and len(i.operands) == 2:
            d, v = i.operands[0], i.operands[1]
            if d.type == 1 and v.type == 2:
                if d.reg == R2 and (v.imm & 0xFFFFFFFF) == choice: got_choice = True
                if d.reg == R1 and (v.imm & 0xFFFFFFFF) == 6:     got_6bit = True
        if i.mnemonic == 'bl' and i.operands and i.operands[0].type == 2 \
           and (i.operands[0].imm & 0xFFFFFFFF) == 0x08093AE4: got_wb = True
        a += i.size
    ck(got_choice, f"{name}: movs r2,#choice {choice:#x}")
    ck(got_6bit and got_wb, f"{name}: 6-bit writeBits (movs r1,#6 + bl 0x08093AE4)")
    ck(bl(blsub) == sub, f"{name}: bl sub-production 0x{sub:08X}")

# ---------------------------------------------------------------------------
# GROUP F — builder name-bit orr immediates (send-site evidence path b)
# ---------------------------------------------------------------------------
print("[F] builder name-bit sets")
BUILDERS = {  # start, end, expected single-bit name orr
    0x08034132: (0x08034230, 0x2,        "SessionSetup"),
    0x08034230: (0x08034324, 0x8,        "ServiceDiscovery"),
    0x080345CC: (0x08034774, 0x2000,     "CPD"),
    0x08034774: (0x08034890, 0x8000000,  "CableCheck"),
    0x08034890: (0x08034A78, 0x20000000, "PreCharge"),
    0x08034A78: (0x08034C30, 0x8000,     "PowerDelivery"),
    0x08034C30: (0x08034E70, 0x80000000, "CurrentDemand"),
    0x08034E70: (0x08034F72, 0x2,        "Welding"),
    0x08034F72: (0x08035050, 0x200000,   "SessionStop"),
}
for b, (end, bit, name) in BUILDERS.items():
    a = b - TB; found = False; gate = False
    while rt(a) < end:
        ins = dis(a)
        if not ins: a += 2; continue
        i = ins[0]
        if i.mnemonic == 'orr' and i.operands and i.operands[-1].type == 2:
            v = i.operands[-1].imm & 0xFFFFFFFF
            if v == bit: found = True
            if v == 2:   gate = True   # W40 DIN gate orr #2 (also Welding/SessionSetup name bit)
        a += i.size
    ck(found, f"{name} builder 0x{b:08X}: name-bit orr #{bit:#x}")
    ck(gate, f"{name} builder: W40 DIN gate orr #2 present")
# CD name-bit at the exact cited address
ck(mn(0x08034CC0) == 'orr' and imm(0x08034CC0) == 0x80000000,
   "CD builder orr #0x80000000 @0x08034CC0 (name-A bit31)")

# ---------------------------------------------------------------------------
# GROUP G — CD application packer 0x0802C2CE body base + PVT unit gate
# ---------------------------------------------------------------------------
print("[G] CD packer 0x0802C2CE")
ck(is_mn(0x0802C2E4, 'add', 'adds') and imm(0x0802C2E4) == 0x1400
   and ops(0x0802C2E4).startswith('r4, r1'), "packer adds.w r4,r1,#0x1400 (body base)")
for pa in (0x0802C2F0, 0x0802C3B0, 0x0802C3D2, 0x0802C3F2, 0x0802C3FC, 0x0802C4AE, 0x0802C4FA):
    ck(mn(pa) == 'orr' and imm(pa) == 0x10000, f"packer PVT unit orr #0x10000 @0x{pa:08X}")

# ---------------------------------------------------------------------------
# GROUP H — ev17 DC_EVStatus 0x0806A936 field reads
# ---------------------------------------------------------------------------
print("[H] ev17 DC_EVStatus field reads")
ck(is_mn(0x0806A97A, 'ldr') and memdisp(0x0806A97A) in (0, None), "ev17 ldr [r4] EVReady")
ck(mn(0x0806A98E) == 'ldrb' and memdisp(0x0806A98E) == 8,    "ev17 gate ldrb [r4,#8]")
ck(is_mn(0x0806A9AE, 'ldr') and memdisp(0x0806A9AE) == 4,    "ev17 ldr [r4,#4] EVErrorCode")
ck(mn(0x0806A9C2) == 'ldrb' and memdisp(0x0806A9C2) == 0x10, "ev17 gate ldrb [r4,#0x10]")
ck(is_mn(0x0806A9FC, 'ldr') and memdisp(0x0806A9FC) == 0xc,  "ev17 ldr [r4,#0xc]")
ck(mn(0x0806AA2A) == 'ldrb' and memdisp(0x0806AA2A) == 0x11, "ev17 ldrb [r4,#0x11] EVRESSSOC")
ck(is_mn(0x0806AA64, 'ldrsb') and memdisp(0x0806AA64) == 0x12,"ev17 ldrsb [r4,#0x12]")
ck(0x08093982 in [t for _, t in bl_targets(0x0806A936, 120)],
   "ev17 uses unsigned-int/enum encoder 0x08093982")

# ---------------------------------------------------------------------------
# GROUP I — ev11 CurrentDemandReq 0x0806BDDC prologue offsets + gates
# ---------------------------------------------------------------------------
print("[I] ev11 CurrentDemandReq grammar")
for addr, off, rd in ((0x0806BDE6, 0x28, R8), (0x0806BDEA, 0x34, R7),
                      (0x0806BDEE, 0x58, R6), (0x0806BDF2, 0x64, R5)):
    ck(is_mn(addr, 'add') and imm(addr) == off and dest(addr) == rd,
       f"ev11 prologue add r?,r4,#0x{off:x} @0x{addr:08X}")
ck(bl(0x0806BE36) == 0x0806A936, "ev11 gid93 bl ev17 DC_EVStatus")
for ga, off in ((0x0806BE58, 0x24), (0x0806BE7A, 0x30), (0x0806BE8A, 0x3c),
                (0x0806BE9A, 0x44), (0x0806BF98, 0x54), (0x0806BFBA, 0x60)):
    ck(is_mn(ga, 'ldrb') and memdisp(ga) == off, f"ev11 gate ldrb [r4,#0x{off:x}] @0x{ga:08X}")
ck(bl(0x0806BF52) == 0x08093982, "ev11 bl 0x08093982 ([0x40] BulkChargingComplete)")
ck(bl(0x0806BF82) == 0x08093982, "ev11 bl 0x08093982 ([0x48] ChargingComplete)")
cd_bls = [t for _, t in bl_targets(0x0806BDDC, 220)]
ck(0x0806A3AC in cd_bls, "ev11 calls PVT encoder 0x0806A3AC")
ck(0x0806A936 in cd_bls, "ev11 calls DC_EVStatus ev17")

# ---------------------------------------------------------------------------
# GROUP J — ev42 SessionStopReq 0x0806AB0E EMPTY body
# ---------------------------------------------------------------------------
print("[J] ev42 SessionStopReq empty")
ck(mn(0x0806AB0E) == 'movs' and imm(0x0806AB0E) == 0 and dest(0x0806AB0E) == R2,
   "ev42 movs r2,#0")
ck(mn(0x0806AB10) == 'movs' and imm(0x0806AB10) == 1 and dest(0x0806AB10) == R1,
   "ev42 movs r1,#1")
ck(is_mn(0x0806AB12, 'b') and bl(0x0806AB12) == 0x08093AE4, "ev42 b.w writeBits(1,0) — EMPTY")

# ---------------------------------------------------------------------------
# GROUP K — ev40 SessionSetupReq 0x0806ABEA EVCCID octet string
# ---------------------------------------------------------------------------
print("[K] ev40 SessionSetupReq EVCCID")
ck(mn(0x0806AC06) == 'ldrh' and memdisp(0x0806AC06) == 8, "ev40 ldrh [r4,#8] len")
ck(bl(0x0806AC0A) == 0x0809392A, "ev40 bl varlen length 0x0809392A")
ck(mn(0x0806AC10) == 'ldrh' and memdisp(0x0806AC10) == 8, "ev40 ldrh [r4,#8] len (2nd)")
ck(bl(0x0806AC16) == 0x08093B5E, "ev40 bl octet-string 0x08093B5E (EVCCID)")

# ---------------------------------------------------------------------------
# GROUP L — ev3c ServiceDiscoveryReq 0x0806B06A optional gates
# ---------------------------------------------------------------------------
print("[L] ev3c ServiceDiscoveryReq")
ck(is_mn(0x0806B06E, 'ldr') and memdisp(0x0806B06E) == 0x24, "ev3c gate ldr [r4,#0x24]")
ck(mn(0x0806B08E) == 'ldrh' and memdisp(0x0806B08E) == 0x22, "ev3c ldrh [r4,#0x22] scope len")
ck(bl(0x0806B096) == 0x0809392A, "ev3c bl varlen length 0x0809392A")
ck(bl(0x0806B0A2) == 0x08093AA0, "ev3c bl string/octet 0x08093AA0 (ServiceScope)")
ck(mn(0x0806B0B6) == 'lsls' and imm(0x0806B0B6) == 0xf, "ev3c lsls #0xf (ServiceCategory bit16 gate)")

# ---------------------------------------------------------------------------
# GROUP M — ev0b ChargeParameterDiscoveryReq 0x0806CEF0 mode + choice subs
# ---------------------------------------------------------------------------
print("[M] ev0b CPD Req")
ck(mn(0x0806CF0C) == 'ldrb' and memdisp(0x0806CF0C) == 0, "ev0b ldrb [r4] EnergyTransferMode")
ck(mn(0x0806CF0E) == 'movs' and imm(0x0806CF0E) == 3, "ev0b writeBits(3,...) mode")
ck(is_mn(0x0806CF24, 'ldrb') and memdisp(0x0806CF24) == 0x30, "ev0b AC gate [r4,#0x30]")
ck(is_mn(0x0806CF44, 'ldrb') and memdisp(0x0806CF44) == 0x80, "ev0b DC gate [r4,#0x80]")
ck(is_mn(0x0806CF64, 'ldrb') and memdisp(0x0806CF64) == 8,    "ev0b gate [r4,#8]")
ck(bl(0x0806CF3E) == 0x0806CE20, "ev0b bl AC_EVChargeParameter ev00 0x0806CE20")
ck(bl(0x0806CF5E) == 0x0806CC3A, "ev0b bl DC_EVChargeParameter ev13 0x0806CC3A")
ck(bl(0x0806CF7A) == 0x0806CC32, "ev0b bl ev1b 0x0806CC32")

# ---------------------------------------------------------------------------
# GROUP N — ev04 CableCheck / ev4e Welding: DC_EVStatus only
# ---------------------------------------------------------------------------
print("[N] ev04 CableCheck / ev4e Welding")
ck(bl(0x0806D6AC) == 0x0806A936, "ev04 CableCheck bl ev17 DC_EVStatus")
ck(bl(0x0806AAA6) == 0x0806A936, "ev4e Welding bl ev17 DC_EVStatus")

# ---------------------------------------------------------------------------
# GROUP O — ev2f PreChargeReq 0x0806B4DE: DC_EVStatus + 2 PVT
# ---------------------------------------------------------------------------
print("[O] ev2f PreChargeReq")
ck(bl(0x0806B4FA) == 0x0806A936, "ev2f bl ev17 DC_EVStatus")
ck(is_mn(0x0806B514, 'add') and imm(0x0806B514) == 0x14, "ev2f PVT arg add r1,r4,#0x14 (EVTargetCurrent)")
ck(bl(0x0806B51A) == 0x0806A3AC, "ev2f bl PVT encoder 0x0806A3AC (EVTargetCurrent)")
ck(is_mn(0x0806B52E, 'add') and imm(0x0806B52E) == 0x1c, "ev2f PVT arg add r1,r4,#0x1c (EVTargetVoltage)")
ck(bl(0x0806B534) == 0x0806A3AC, "ev2f bl PVT encoder 0x0806A3AC (EVTargetVoltage)")

# ---------------------------------------------------------------------------
# GROUP P — ev2d PowerDeliveryReq DIN + ev26 ISO variant
# ---------------------------------------------------------------------------
print("[P] ev2d PowerDeliveryReq (DIN) / ev26 (ISO)")
ck(bl(0x0806B854) == 0x08093982, "ev2d ChargeProgress enum via 0x08093982")
ck(is_mn(0x0806B86E, 'ldrb') and memdisp(0x0806B86E) == 0xcc, "ev2d gate [r4,#0xcc]")
ck(is_mn(0x0806B88E, 'ldrb') and memdisp(0x0806B88E) == 0xf8, "ev2d gate [r4,#0xf8]")
ck(is_mn(0x0806B8BC, 'ldrb') and memdisp(0x0806B8BC) == 0xd4, "ev2d gate [r4,#0xd4]")
ck(bl(0x0806B886) == 0x08070588, "ev2d bl optional-param sub 0x08070588")
ck(bl(0x0806B8B6) == 0x0806B6F8, "ev2d bl ev14 DC_EVStatus 0x0806B6F8")
ck(bl(0x0806B8CE) == 0x0806B6F0, "ev2d bl ev1c empty 0x0806B6F0")
ck(is_mn(0x0806BB8C, 'ldrb') and memdisp(0x0806BB8C) in (0, None), "ISO ev26 ldrb [r4] ChargeProgress")
ck(mn(0x0806BB8E) == 'movs' and imm(0x0806BB8E) == 5, "ISO ev26 ChargeProgress writeBits(5,...)")
ck(bl(0x0806BBB4) == 0x0806B55A, "ISO ev26 bl ev02 DC_EVPowerDeliveryParameter 0x0806B55A")

# ---------------------------------------------------------------------------
# GROUP Q — ev02 DC_EVPowerDeliveryParameter 0x0806B55A
# ---------------------------------------------------------------------------
print("[Q] ev02 DC_EVPowerDeliveryParameter")
ck(bl(0x0806B59C) == 0x08093982, "ev02 bl 0x08093982 ([r4])")
ck(bl(0x0806B5CA) == 0x08093982, "ev02 bl 0x08093982 ([r4+4])")

# ---------------------------------------------------------------------------
# GROUP R — decoder tbb (0x080699BC) flag cross-check: encoder ev == decoder ev
# ---------------------------------------------------------------------------
print("[R] decoder tbb flag cross-check")
def stub_info(addr):
    """follow b-thunks; first bl (decoder) + orr flag (word,bit). (from analyze93.py)"""
    a = addr; dec = None; flag = None; seq = []
    for _ in range(14):
        ins = dis(a - TB)
        if not ins: break
        i = ins[0]; m = i.mnemonic.split('.')[0]; op = i.operands
        if m == 'b' and op and op[0].type == 2 and dec is None:
            a = op[0].imm & 0xFFFFFFFF; continue
        seq.append(i)
        if m == 'bl' and op and op[0].type == 2 and dec is None:
            dec = op[0].imm & 0xFFFFFFFF
        if m == 'orr' and len(op) >= 3 and op[2].type == 2 and dec is not None and flag is None:
            bit = op[2].imm & 0xFFFFFFFF
            if bit: flag = bit.bit_length() - 1
        if m == 'b' and dec is not None: break
        a += i.size
    word = None
    for i in seq:
        if i.mnemonic.split('.')[0] == 'ldr' and len(i.operands) >= 2 and i.operands[1].type == 3:
            d = i.operands[1].mem.disp
            if d in (0x140, 0x144, 0x148): word = 0x4140 + (d - 0x140)
    return dec, word, flag

t = 0x080699BC - TB
table = [fw[t + k] for k in range(81)]
# sub-ev -> expected flag word.bit (matches encoder direct-dispatch chain)
EXPECT = {0x40: (0x4144, 21), 0x3C: (0x4144, 15), 0x0B: (0x4148, 13),
          0x04: (0x4144, 23), 0x2F: (0x4148, 6),  0x2D: (0x4148, 1),
          0x11: (0x4148, 5),  0x4E: (0x4144, 29), 0x42: (0x4148, 10),
          0x4D: (0x4140, 1)}
for ev, (ew, eb) in EXPECT.items():
    stub = 0x080699BC + 2 * table[ev]
    dec, word, bit = stub_info(stub)
    ck(word == ew and bit == eb,
       f"decoder ev{ev:02x} flag == {ew:x}.{eb} (got {word and hex(word)}.{bit})")

# ---------------------------------------------------------------------------
print(f"\n{checks} checks, {failures} failures")
sys.exit(1 if failures else 0)