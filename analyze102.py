#!/usr/bin/env python3
"""analyze102.py — Agent P (gap G3): reproducible assertions for the CCS2 EVCC EXI Res-side
handshake message grammars recovered from C013 (decoded_c013.bin, TB=0x0801FBFE).

Run (cwd = repo root):
  nix-shell -p python3 python3Packages.capstone --run "python3 analyze102.py"

Asserts every load-bearing claim: root tbb event->decoder resolution, the ev4d DIN-document
wrapper, the 6-bit DIN body dispatcher sub-event->decoder+name-flag map, the name-wrapper
bit->code map, per-message field primitive call targets + bit-width immediates + struct offsets,
the leading 1-bit event-code gates, and the application writer meas/evcc_sta offsets.
Prints 'N checks, 0 failures'; exits nonzero on any failure.
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

# capstone ARM register ids
R0,R1,R2,R3,R4,R5,R6,R7,R8,R9,R10,R11,R12 = 66,67,68,69,70,71,72,73,74,75,76,77,78
SP,LR,PC = 79,80,81

NCHK=0; NFAIL=0; FAILED=[]
def chk(name, cond):
    global NCHK,NFAIL
    NCHK+=1
    if not cond:
        NFAIL+=1; FAILED.append(name)
        print(f"  FAIL: {name}")

def I(addr):
    ins=dis(addr-TB)
    return ins[0] if ins else None
def mn(addr):
    i=I(addr); return i.mnemonic.split('.')[0] if i else None
def ops(addr):
    i=I(addr); return i.operands if i else []

def bl_is(addr, target):
    i=I(addr)
    return bool(i and i.mnemonic=='bl' and i.operands and i.operands[0].type==2
                and (i.operands[0].imm&0xFFFFFFFF)==target)
def rb_width(bl_addr):
    # last `movs r1,#imm` in the 16 bytes before the readBits-wrapper bl
    o=bl_addr-16-TB; last=None
    while o < bl_addr-TB:
        ins=list(md.disasm(fw[o:o+8],rt(o),count=1))
        if not ins: o+=2; continue
        i=ins[0]
        if i.mnemonic=='movs' and len(i.operands)>=2 and i.operands[0].type==1 \
           and i.operands[0].reg==R1 and i.operands[1].type==2:
            last=i.operands[1].imm
        o+=i.size
    return last
def rb(addr, n):
    return bl_is(addr,0x08093660) and rb_width(addr)==n
def add_r1(addr, base, off):
    i=I(addr)
    if not i or i.mnemonic.split('.')[0] not in ('add','adds'): return False
    o=i.operands
    return len(o)>=3 and o[0].type==1 and o[0].reg==R1 and o[1].type==1 and o[1].reg==base \
           and o[2].type==2 and o[2].imm==off
def mov_r1(addr, base):
    i=I(addr)
    return bool(i and i.mnemonic=='mov' and len(i.operands)>=2 and i.operands[0].reg==R1
                and i.operands[1].type==1 and i.operands[1].reg==base)
def movw_is(addr, reg, imm):
    # accept MOVW (16-bit) and MOV.W (modified-immediate) forms
    i=I(addr)
    return bool(i and i.mnemonic.split('.')[0] in ('movw','mov') and len(i.operands)>=2
                and i.operands[0].reg==reg and i.operands[1].type==2 and (i.operands[1].imm&0xFFFF)==imm)
def add_r2(addr, base, off):
    i=I(addr)
    if not i or i.mnemonic.split('.')[0] not in ('add','adds'): return False
    o=i.operands
    return len(o)>=3 and o[0].type==1 and o[0].reg==R2 and o[1].type==1 and o[1].reg==base \
           and o[2].type==2 and o[2].imm==off
def strb_off(addr, base, off):
    i=I(addr)
    if not i or i.mnemonic.split('.')[0] not in ('strb',): return False
    o=i.operands
    return len(o)>=2 and o[1].type==3 and o[1].mem.base==base and o[1].mem.disp==off
def ldrb_off(addr, base, off):
    i=I(addr)
    if not i or i.mnemonic.split('.')[0] not in ('ldrb',): return False
    o=i.operands
    return len(o)>=2 and o[1].type==3 and o[1].mem.base==base and o[1].mem.disp==off
def str_off(addr, base, off):
    i=I(addr)
    if not i or i.mnemonic.split('.')[0] not in ('str',): return False
    o=i.operands
    return len(o)>=2 and o[1].type==3 and o[1].mem.base==base and o[1].mem.disp==off
def cmp_is(addr, imm):
    i=I(addr)
    return bool(i and i.mnemonic=='cmp' and len(i.operands)>=2 and i.operands[1].type==2
                and i.operands[1].imm==imm)
def lsls_is(addr, imm):
    # 3-operand form `lsls rd, rm, #imm` -> shift imm is the LAST operand
    i=I(addr)
    return bool(i and i.mnemonic=='lsls' and len(i.operands)>=2 and i.operands[-1].type==2
                and i.operands[-1].imm==imm)

# ---- root tbb event -> decoder (7-bit root, tbb @0x080699B8, table base 0x080699BC) ----
def root_dec(ev):
    tt=0x080699BC-TB
    stub=0x080699BC+2*fw[tt+ev]
    a=stub-TB
    for _ in range(24):
        ins=dis(a)
        if not ins: return None
        i=ins[0]; m=i.mnemonic.split('.')[0]; o=i.operands
        if m=='b' and o and o[0].type==2: a=(o[0].imm&0xFFFFFFFF)-TB; continue
        if m=='bl' and o and o[0].type==2: return o[0].imm&0xFFFFFFFF
        a+=i.size
    return None

print("== root tbb event -> decoder ==")
for ev,dec,nm in [(0x4d,0x0806A33E,"DIN-document"),(0x41,0x08062B1E,"SessionSetupRes"),
                  (0x3d,0x08063370,"ServiceDiscoveryRes"),(0x0c,0x08065BFC,"CPDRes"),
                  (0x2e,0x08063DBA,"PowerDeliveryRes"),(0x4f,0x08062754,"WeldingRes"),
                  (0x15,0x080650D2,"DC_EVSEChargeParam"),(0x1d,0x080650AC,"empty-gate"),
                  (0x05,0x08066C5C,"CableCheckRes"),(0x30,0x08063A8A,"PreChargeRes"),
                  (0x12,0x0806471E,"CurrentDemandRes")]:
    chk(f"root ev{ev:02x} -> {nm} 0x{dec:08X}", root_dec(ev)==dec)

# ---- ev4d DIN-document wrapper: gate + Header + gate + DIN-dispatcher(msg+0x1400) + gate ----
print("== ev4d DIN-document wrapper 0x0806A33E ==")
chk("ev4d Header call 0x0806978A", bl_is(0x0806A364,0x0806978A))
chk("ev4d body base msg+0x1400", add_r1(0x0806A382,R5,0x1400))
chk("ev4d DIN-dispatcher call 0x08066DD0", bl_is(0x0806A388,0x08066DD0))
chk("ev4d leading gate readBits1", rb(0x0806A354,1))
chk("ev4d mid gate readBits1", rb(0x0806A372,1))
chk("ev4d trailing gate readBits1", rb(0x0806A396,1))

# ---- DIN body dispatcher 0x08066DD0: 6-bit sub-event, cmp#0x24, tbb@0x08066E02 ----
print("== DIN body dispatcher 0x08066DD0 ==")
chk("dispatcher readBits6", rb(0x08066DEA,6))
chk("dispatcher cmp #0x24 (36)", cmp_is(0x08066DFE,0x24))
chk("dispatcher name-flag word0 movw #0x2d38", movw_is(0x08066DF2,R2,0x2d38))
def din_case(k):
    base=0x08066E06
    tgt=base+2*fw[base-TB+k]
    a=tgt-TB; dec=None; flag=None; word=None
    for _ in range(20):
        ins=dis(a)
        if not ins: break
        i=ins[0]; m=i.mnemonic.split('.')[0]; o=i.operands
        if m=='b' and o and o[0].type==2:
            if dec is None: a=(o[0].imm&0xFFFFFFFF)-TB; continue
            break
        if m=='bl' and o and o[0].type==2 and dec is None: dec=o[0].imm&0xFFFFFFFF
        if m=='ldr' and dec is not None and flag is None and len(o)>=2 and o[1].type==3:
            word=o[1].mem.base
        if m=='orr' and len(o)>=3 and o[2].type==2 and dec is not None and flag is None:
            flag=o[2].imm&0xFFFFFFFF
        if m=='str' and dec is not None and flag is not None: break
        a+=i.size
    return dec,flag,word
for k,dec,flag,word,nm in [(30,0x08062B1E,0x4,R4,"SessionSetup bit2"),
                           (26,0x08063370,0x10,R4,"ServiceDiscovery bit4"),
                           (8,0x08065BFC,0x4000,R4,"CPD bit14"),
                           (20,0x08063DBA,0x10000,R4,"PowerDelivery bit16"),
                           (34,0x08062754,0x4,R6,"Welding word1.bit2"),
                           (2,0x08066C5C,0x10000000,R4,"CableCheck bit28"),
                           (22,0x08063A8A,0x40000000,R4,"PreCharge bit30"),
                           (14,0x0806471E,0x1,R6,"CurrentDemand word1.bit0")]:
    d,f,w=din_case(k)
    chk(f"DIN subev{k} -> {nm}", d==dec and f==flag and w==word)

# ---- name wrapper 0x08033CBC: gate doc+0x4140.bit1, bit->code ----
print("== name wrapper 0x08033CBC ==")
chk("name gate ldrb doc+0x4140", ldrb_off(0x08033CC0,R6,0x140))
chk("name gate bit1 (lsls#0x1e)", lsls_is(0x08033CC4,0x1e))
chk("name word0 ldr doc+0x4138", mn(0x08033CC8)=='ldr')
chk("SessionSetup bit2 (lsls#0x1d)", lsls_is(0x08033CCC,0x1d))
chk("ServiceDiscovery bit4 (lsls#0x1b)", lsls_is(0x08033CE4,0x1b))
chk("CPD bit14 (lsls#0x11)", lsls_is(0x08033D5C,0x11))
chk("PowerDelivery bit16 (lsls#0xf)", lsls_is(0x08033D74,0xf))

# ---- SessionSetupRes ev41 0x08062B1E ----
print("== SessionSetupRes ev41 ==")
chk("SS init 0x08061ec6", bl_is(0x08062B2C,0x08061EC6))
chk("SS lead gate1 rb1", rb(0x08062B4E,1))
chk("SS lead gate2 rb1", rb(0x08062B60,1))
chk("SS RC rb5", rb(0x08062B74,5))
chk("SS RC strb [msg+0]", strb_off(0x08062B7A,R7,0))
chk("SS post-RC gate rb1", rb(0x08062B86,1))
chk("SS EVSEID len dest msg+0x22", add_r1(0x08062BC8,R7,0x22))
chk("SS EVSEID len u16 0x08093404", bl_is(0x08062BCE,0x08093404))
chk("SS EVSEID len clamp cmp#0x20", cmp_is(0x08062BD8,0x20))
chk("SS EVSEID bytes dest msg+2 (r2)", add_r2(0x08062BDC,R7,2))
chk("SS EVSEID bytes prim 0x080936de", bl_is(0x08062BE0,0x080936DE))
chk("SS timestamp choice rb2", rb(0x08062C02,2))
chk("SS timestamp dest msg+0x28", add_r1(0x08062C30,R7,0x28))
chk("SS timestamp prim 0x08093550", bl_is(0x08062C36,0x08093550))
chk("SS timestamp present str [msg+0x30]", str_off(0x08062C3C,R7,0x30))

# ---- ServiceDiscoveryRes ev3d 0x08063370 ----
print("== ServiceDiscoveryRes ev3d ==")
chk("SD init 0x08061e44", bl_is(0x08063380,0x08061E44))
chk("SD RC rb5", rb(0x080633D2,5))
chk("SD RC strb [msg+0]", strb_off(0x080633D8,R6,0))
chk("SD charge-service dest msg+2", add_r1(0x0806340C,R6,2))
chk("SD charge-service sub 0x0806327a", bl_is(0x08063410,0x0806327A))
chk("SD ServiceList dest msg+0xc", add_r1(0x0806342C,R6,0xc))
chk("SD ServiceList ev39 0x0806316a", bl_is(0x08063432,0x0806316A))
chk("SD energy choice rb2", rb(0x08063440,2))
chk("SD energy dest msg+0x64", add_r1(0x08063452,R6,0x64))
chk("SD energy sub 0x0806a192", bl_is(0x08063458,0x0806A192))
chk("SD energy present str [msg+0x308]", str_off(0x08063460,R6,0x308))
chk("SD charge-service max5 cmp#5", cmp_is(0x080632A4,5))
chk("SD energy max8 cmp#8", cmp_is(0x0806A1BC,8))
chk("SD energy count ldrh [sub+0x2a0]", mn(0x0806A1B4)=='ldrh')
# ServiceType element 0x08062EDC (reused by ServiceList + EnergyTransferModeList)
chk("SvcType ServiceID u16 0x08093404", bl_is(0x08062F48,0x08093404))
chk("SvcType ServiceName choice rb2", rb(0x08062F70,2))
chk("SvcType ServiceName len dest msg+0x24", add_r1(0x08062F94,R9,0x24))
chk("SvcType ServiceName len u16", bl_is(0x08062F9A,0x08093404))
# EnergyTransferMode element 0x080630D4
chk("Energy elem reuses SvcType 0x08062edc", bl_is(0x080630FA,0x08062EDC))
chk("Energy elem bool dest msg+0x50", add_r1(0x08063130,R5,0x50))
chk("Energy elem bool prim 0x080934be", bl_is(0x08063136,0x080934BE))

# ---- CPDRes ev0c 0x08065BFC + DCparam ev15 ----
print("== CPDRes ev0c ==")
chk("CPD init 0x08061d9a", bl_is(0x08065C0C,0x08061D9A))
chk("CPD RC rb5", rb(0x08065C62,5))
chk("CPD RC strb [msg+0]", strb_off(0x08065C68,R9,0))
chk("CPD state0x73 rb1", rb(0x08065CBA,1))
chk("CPD state0x73 strb [msg+1]", strb_off(0x08065CC0,R9,1))
chk("CPD handler case6 branches body+1==1 (cmp#1)", cmp_is(0x08036044,1))
chk("CPD state0x74 choice rb2", rb(0x08065CE2,2))
chk("CPD AC-sched dest msg+0xc", add_r1(0x08065D08,R9,0xc))
chk("CPD AC-sched ev35 0x08065b62", bl_is(0x08065D0E,0x08065B62))
chk("CPD state0x74 empty dest msg+4", add_r1(0x08065CF2,R9,4))
chk("CPD state0x74 empty ev36 0x08065368", bl_is(0x08065CF8,0x08065368))
chk("CPD state0x75 choice rb2", rb(0x08065D22,2))
chk("CPD AC-param dest msg+0x28a8", movw_is(0x08065D5C,R1,0x28a8))
chk("CPD AC-param ev01 0x08065296", bl_is(0x08065D64,0x08065296))
chk("CPD DC-param dest msg+0x28d4", movw_is(0x08065D6E,R1,0x28d4))
chk("CPD DC-param ev15 0x080650d2", bl_is(0x08065D76,0x080650D2))
chk("CPD empty dest msg+0x28a0", movw_is(0x08065D36,R1,0x28a0))
chk("CPD empty ev1d 0x080650ac", bl_is(0x08065D3E,0x080650AC))
chk("ev1d is 1-bit gate rb1", rb(0x080650C0,1))
chk("ev36 is 1-bit gate rb1", rb(0x0806537C,1))

print("== DC_EVSEChargeParam ev15 ==")
chk("DCparam init 0x08061cfc", bl_is(0x080650E2,0x08061CFC))
chk("DCparam r8=msg+0x20", add_r1(0x080650E6,R8,0x20) or mn(0x080650E6)=='add')
chk("DCparam DC_EVSEStatus dest msg+0", mov_r1(0x0806513A,R5))
chk("DCparam DC_EVSEStatus 0x0806259e", bl_is(0x0806513E,0x0806259E))
chk("DCparam maxCurrent PVT msg+0xc", add_r1(0x0806515E,R5,0xc))
chk("DCparam maxCurrent PVT prim", bl_is(0x08065164,0x08062070))
chk("DCparam maxPower choice rb2", rb(0x08065172,2))
chk("DCparam maxPower PVT msg+0x14", add_r1(0x08065184,R5,0x14))
chk("DCparam maxPower present [msg+0x1c]", str_off(0x08065190,R5,0x1c))
chk("DCparam maxVoltage PVT r8(msg+0x20)", mov_r1(0x08065196,R8))
chk("DCparam minCurrent PVT msg+0x28", add_r1(0x080651CC,R5,0x28))
chk("DCparam minVoltage PVT msg+0x30", add_r1(0x080651EE,R5,0x30))
chk("DCparam state0x58 choice rb2", rb(0x0806520A,2))
chk("DCparam opt PVT msg+0x38", add_r1(0x0806521C,R5,0x38))
chk("DCparam opt present [msg+0x40]", str_off(0x08065228,R5,0x40))
chk("DCparam PVT r7(msg+0x44)", mov_r1(0x0806522E,R7))
chk("DCparam energy choice rb2", rb(0x08065256,2))
chk("DCparam energy PVT msg+0x4c", add_r1(0x08065268,R5,0x4c))
chk("DCparam energy present [msg+0x54]", str_off(0x08065274,R5,0x54))

# ---- PowerDeliveryRes ev2e 0x08063DBA ----
print("== PowerDeliveryRes ev2e ==")
chk("PD init 0x08061c22", bl_is(0x08063DC8,0x08061C22))
chk("PD lead gate1 rb1", rb(0x08063DD2,1))
chk("PD lead gate2 rb1", rb(0x08063DE4,1))
chk("PD RC rb5", rb(0x08063DFC,5))
chk("PD RC strb [msg+0]", strb_off(0x08063E02,R5,0))
chk("PD post-RC gate rb1", rb(0x08063E0E,1))
chk("PD EVSEStatus choice rb2", rb(0x08063E24,2))
chk("PD choice0 AC dest msg+0xc", add_r1(0x08063E3E,R5,0xc))
chk("PD choice0 AC 0x08063c2a", bl_is(0x08063E44,0x08063C2A))
chk("PD choice0 present [msg+0x1c]", str_off(0x08063E48,R5,0x1c))
chk("PD choice1 DC dest msg+0x20", add_r1(0x08063E4C,R5,0x20))
chk("PD choice1 DC_EVSEStatus 0x0806259e", bl_is(0x08063E52,0x0806259E))
chk("PD choice1 present [msg+0x2c]", str_off(0x08063E56,R5,0x2c))
chk("PD choice2 empty dest msg+4", add_r1(0x08063E5A,R5,4))
chk("PD choice2 empty 0x08063c04", bl_is(0x08063E5E,0x08063C04))
chk("PD choice2 present [msg+8]", str_off(0x08063E62,R5,8))
chk("PD trailing gate rb1", rb(0x08063E6E,1))

# ---- WeldingDetectionRes ev4f 0x08062754 ----
print("== WeldingDetectionRes ev4f ==")
chk("WD init 0x08061c36", bl_is(0x08062760,0x08061C36))
chk("WD lead gate1 rb1", rb(0x0806277A,1))
chk("WD lead gate2 rb1", rb(0x0806278C,1))
chk("WD RC rb5", rb(0x080627A4,5))
chk("WD RC strb [msg+0]", strb_off(0x080627AA,R5,0))
chk("WD post-RC gate rb1", rb(0x080627B6,1))
chk("WD state0xe gate rb1", rb(0x080627D8,1))
chk("WD DC_EVSEStatus dest msg+4", add_r1(0x080627E6,R5,4))
chk("WD DC_EVSEStatus 0x0806259e", bl_is(0x080627EA,0x0806259E))
chk("WD state0xf gate rb1", rb(0x080627F8,1))
chk("WD EVSEPresentVoltage PVT msg+0x10", add_r1(0x08062806,R5,0x10))
chk("WD PVT prim 0x08062070", bl_is(0x0806280C,0x08062070))
chk("WD trailing gate rb1", rb(0x0806281A,1))

# ---- application writers (meas offsets) ----
print("== SessionSetup writer 0x0802BAA8 ==")
chk("SSw body base doc+0x1400", add_r1(0x0802BAB4,R4,0x1400) or mn(0x0802BAB4)=='adds')
chk("SSw EVSEID len ldrh [body+0x22]", mn(0x0802BACA)=='ldrh')
chk("SSw EVSEID dst meas+0x219", mn(0x0802BACE)=='addw' or mn(0x0802BACE)=='add')
chk("SSw memcpy 0x0809e718", bl_is(0x0802BAD2,0x0809E718))
chk("SSw meas[0x3d1e]=7 movw", movw_is(0x0802BAD8,R1,0x3d1e))
chk("SSw timestamp present ldrb [body+0x30]", ldrb_off(0x0802BADE,R4,0x30))
chk("SSw timestamp strd [meas+0x210]", mn(0x0802BAEA)=='strd')
chk("SSw meas[0x24d]=1", mn(0x0802BAF0)=='strb')

print("== ServiceDiscovery writer 0x0802BB38 ==")
chk("SDw meas[0x3cf2]=0 movw", movw_is(0x0802BB56,R1,0x3cf2))
chk("SDw meas[0x3d1e]=7 movw", movw_is(0x0802BB60,R1,0x3d1e))
chk("SDw memcpy dst meas+0x37e0", movw_is(0x0802BB9A,R0,0x37e0))
chk("SDw memcpy len 0x30c", movw_is(0x0802BB9E,R2,0x30c))
chk("SDw memcpy 0x0809e826", bl_is(0x0802BBA6,0x0809E826))
chk("SDw energy count ldrh [body+0x304]", mn(0x0802BBAC)=='ldrh')

print("== CPD writer 0x0802BEC0 ==")
chk("CPDw body[1]->meas[0x3cf2] movw", movw_is(0x0802BED6,R2,0x3cf2))
chk("CPDw body[1] ldrb", ldrb_off(0x0802BEDA,R4,1))
chk("CPDw DCparam+0 movw #0x28d4", movw_is(0x0802BEDE,R0,0x28d4))
chk("CPDw meas[0x3cfc] movw", movw_is(0x0802BEE2,R2,0x3cfc))

print("== PowerDelivery writer 0x0802C72C ==")
chk("PDw meas[0x3cfc] movw", movw_is(0x0802C74A,R1,0x3cfc))
chk("PDw DC_EVSEStatus+0 ldrb [body+0x20]", ldrb_off(0x0802C74E,R5,0x20))
chk("PDw DC_EVSEStatus+2 ldrb [body+0x22]", ldrb_off(0x0802C756,R5,2))
chk("PDw DC_EVSEStatus+8 ldrb [body+0x28]", ldrb_off(0x0802C75C,R5,8))

print("== Welding writer 0x0802C7E2 ==")
chk("WDw meas[0x3cfc] movw", movw_is(0x0802C7EE,R2,0x3cfc))
chk("WDw DC_EVSEStatus+0 ldrb [body+4]", ldrb_off(0x0802C7F2,R4,4))
chk("WDw DC_EVSEStatus+2 ldrb [body+6]", ldrb_off(0x0802C7F8,R4,6))
chk("WDw DC_EVSEStatus+8 ldrb [body+0xc]", ldrb_off(0x0802C7FE,R4,0xc))
chk("WDw PVT value ldrh [body+0x14]", mn(0x0802C802)=='ldrh')
chk("WDw meas[0x3d18] movw", movw_is(0x0802C804,R2,0x3d18))
chk("WDw PVT factor ldrb [body+0x10]", ldrb_off(0x0802C80A,R4,0x10))
chk("WDw factor+3", mn(0x0802C80E)=='adds')

print(f"\n{NCHK} checks, {NFAIL} failures")
if NFAIL:
    print("FAILED:"); [print("  -",f) for f in FAILED]
    raise SystemExit(1)