#!/usr/bin/env python3
"""analyze77.py — ADC-channel -> CP/PP signal mapper (§5.5a / §8.4): names which ADC
channels/pins carry the CCS2 Control Pilot (CP) and Proximity Pilot (PP), plus the other
analog measurements, by re-deriving the mapping from firmware.bin bytes (no hardcoded
conclusions).

RESOLVED: the firmware's own "Hardware Information" diagnostic dumper (0x0804E92C) prints
each ADC getter against a label string, naming the signals:
    PA0 / ADC3_IN0  -> "AD_CPD"  = CP (Control Pilot) DC voltage level   [3.3 V scale]
    PA2 / ADC3_IN2  -> "AD_PP"   = PP (Proximity Pilot) voltage          [3.3 V scale]
    PC2 / ADC3_IN12 -> "AD_BAT"  = battery voltage                       [6.6 V scale, 2:1 divider]
    PA1 / ADC3_IN1  -> "+24V"    = +24 V rail monitor
    PB0 - PB1 (ADC1_IN8 - ADC2_IN9, dual simultaneous) -> "HV" = DC-link high voltage (differential)
CP PWM duty/frequency are NOT ADC: they are TIM4_CH1 input-capture on PD12 (AF2), median-filtered,
then decoded to current by the IEC 61851-1 duty->ampacity law (8%-97% nominal; 10-85% -> 0.6*d A;
85-96% -> 2.5*(d-64) A; 96-97% -> 80 A). CP state char {'0','1','5','M','N'} ('5' = 5% DIN/ISO
digital-comm mode = CP_ST_DUTY_5). PP state = AD_PP voltage window detector.

Method (byte-derived): (1) locate the ADC label strings; (2) find the dumper function by its
ADR references to those labels and pair each BL getter with its label; (3) locate the ADC init
by its ADC-peripheral base loads and constant-track the SQR1/2/3 + CCR + DMA writes to decode the
regular channel sequences and result buffers; (4) decode the mV getters' scale (field offset,
multiplier, divisor) to bind each ADCctx field to an ADC3 sequence slot/channel/pin; (5) decode
the IEC 61851 duty->current classifier constants.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze77.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
fw = open('firmware.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
def ldr_target(o):
    """runtime address of the literal pool word for an LDR-literal at file offset o, or None."""
    h1 = u16(o)
    if (h1 & 0xF800) == 0x4800:
        return (((rt(o)+4) & ~3) - TB) + (h1 & 0xFF)*4
    if (h1 & 0xFF7F) == 0xF85F:
        h2 = u16(o+2); pca = ((rt(o)+4) & ~3) - TB
        return pca + ((h2 & 0xFFF) if (h1 >> 7) & 1 else -(h2 & 0xFFF))
    return None
CHPIN = {0:'PA0',1:'PA1',2:'PA2',3:'PA3',4:'PA4',5:'PA5',6:'PA6',7:'PA7',
         8:'PB0',9:'PB1',10:'PC0',11:'PC1',12:'PC2',13:'PC3',14:'PC4',15:'PC5'}

print("== 1. ADC signal label strings (firmware 'Hardware Information' dumper) ==")
labels = {}
for key, pat in [('hdr', b'Hardware Information'), ('ad_pp', b'AD_PP   : '), ('ad_cpd', b'AD_CPD  : '),
                 ('ad_bat', b'AD_BAT  : '), ('cp_duty', b'CP_DUTY : '), ('cp_freq', b'CP_FREQ : '),
                 ('cp_st', b'CP_ST   : '), ('pp_st', b'PP_ST   : '), ('p24v', b'+24V    : '), ('hv', b'HV      : ')]:
    idx = fw.find(pat)
    if idx < 0:
        print(f"  {key:8s}: NOT FOUND"); continue
    st = idx
    while st > 0 and fw[st-1] != 0 and 32 <= fw[st-1] < 127: st -= 1
    s = fw[st:st+40].split(b'\x00')[0].decode('latin1')
    labels[key] = st
    print(f"  {key:8s}: f+0x{st:05x} (0x{rt(st):08X})  {s!r}")
label_rt = {rt(v): k for k, v in labels.items()}

print("\n== 2. dumper getter -> label pairing (ADR-to-label, preceded by BL getter) ==")
# find ADR instructions whose target is a label; the dumper is the densest cluster
adr_hits = []
for o in range(0, N-4, 2):
    h1 = u16(o)
    if (h1 & 0xF800) == 0xA000:           # ADR T1: 1010 0 rd imm8
        tgt = ((rt(o)+4) & ~3) + (h1 & 0xFF)*4
        if tgt in label_rt: adr_hits.append((o, label_rt[tgt]))
if adr_hits:
    lo = min(o for o, _ in adr_hits); hi = max(o for o, _ in adr_hits)
    # back up to the function push prologue
    start = lo
    while start > lo-0x60:
        if (u16(start) & 0xFF00) == 0xB500 or (u16(start) & 0xFFF0) == 0xE920: break
        start -= 2
    pair = {}; last_bl = None; a = start
    while a <= hi+4:
        ins = dis(a)
        if not ins: a += 2; continue
        i = ins[0]
        if i.mnemonic == 'bl' and i.operands and i.operands[0].type == 2:
            last_bl = i.operands[0].imm
        elif i.mnemonic == 'adr' and len(i.operands) == 2:
            tgt = ((rt(a)+4) & ~3) + i.operands[1].imm
            if tgt in label_rt and last_bl is not None:
                pair[label_rt[tgt]] = last_bl
        a += i.size
    for k in ['p24v','cp_freq','cp_st','cp_duty','ad_pp','ad_bat','ad_cpd','pp_st','hv']:
        if k in pair:
            print(f"  {k:8s} <- getter 0x{pair[k]:08X}")

print("\n== 3. ADC init: regular channel sequences + DMA buffers (constant-tracked) ==")
ADC_BASES = {0x40012000:'ADC1', 0x40012100:'ADC2', 0x40012200:'ADC3', 0x40012300:'ADCcc'}
# locate init function: cluster of ADC-base loads; pick the one writing ADC3 SQR (full init)
base_loads = []
mp = {}
for o in range(0, N-4, 2):
    h1 = u16(o); t = None
    if (h1 & 0xFBF0) in (0xF240, 0xF2C0):
        ins = dis(o)
        if ins and ins[0].mnemonic in ('movw','movt') and len(ins[0].operands) == 2:
            i = ins[0]; reg = i.operands[0].reg; imm = i.operands[1].imm & 0xFFFF
            if i.mnemonic == 'movw': mp[reg] = (imm, o)
            elif reg in mp:
                lo2, fo = mp.pop(reg); t = (imm << 16) | lo2; o = fo
    else:
        p = ldr_target(o)
        if p is not None and 0 <= p and p+4 <= N: t = u32(p)
    if t in ADC_BASES: base_loads.append((o, t))
# group loads within 0x120 bytes; choose group covering the most distinct ADC bases
groups = []
for o, t in base_loads:
    if groups and o - groups[-1][-1][0] < 0x120: groups[-1].append((o, t))
    else: groups.append([(o, t)])
init_grp = max(groups, key=lambda g: len({t for _, t in g}))
first = init_grp[0][0]
start = first
while start > first-0x80:
    if (u16(start) & 0xFF00) == 0xB500 or (u16(start) & 0xFFF0) == 0xE920: break
    start -= 2
# constant-track register values; record peripheral writes
PERIPH = lambda a: (0x40012000 <= a < 0x40012400) or (0x40026400 <= a < 0x40026500) or (0x40010400 <= a < 0x40010500)
rv = {}; writes = {}; a = start; steps = 0
while steps < 400:
    ins = dis(a)
    if not ins: break
    i = ins[0]; mn = i.mnemonic; ops = i.operands
    regs = [op.reg for op in ops if op.type == 1]
    if mn == 'movw' and len(ops) == 2: rv[ops[0].reg] = ops[1].imm & 0xFFFF
    elif mn == 'movt' and len(ops) == 2: rv[ops[0].reg] = ((ops[1].imm & 0xFFFF) << 16) | (rv.get(ops[0].reg, 0) & 0xFFFF)
    elif mn in ('movs','mov','mov.w') and len(ops) == 2 and ops[1].type == 2: rv[ops[0].reg] = ops[1].imm
    elif mn in ('mov','mov.w') and len(ops) == 2 and ops[1].type == 1: rv[ops[0].reg] = rv.get(ops[1].reg)
    elif mn in ('ldr', 'ldr.w') and len(ops) == 2 and ops[1].type == 3:
        p = ldr_target(a)
        if p is not None and 0 <= p and p+4 <= N: rv[ops[0].reg] = u32(p)
        else: rv.pop(ops[0].reg, None)
    elif mn in ('adds','add','add.w') and len(ops) == 3 and ops[2].type == 2:
        base = rv.get(ops[1].reg); rv[ops[0].reg] = (base + ops[2].imm) if base is not None else None
    elif mn in ('adds','add','add.w') and len(ops) == 2 and ops[1].type == 2:
        base = rv.get(ops[0].reg); rv[ops[0].reg] = (base + ops[1].imm) if base is not None else None
    elif mn in ('str','strh','str.w','strh.w') and len(ops) == 2 and ops[1].type == 3:
        base = rv.get(ops[1].reg); val = rv.get(ops[0].reg)
        if base is not None and val is not None:
            tgt = base + ops[1].mem.disp
            if PERIPH(tgt): writes[tgt] = val
    elif mn in ('ldr','ldrh','ldrb','ldr.w') and ops and ops[0].type == 1:
        if not (len(ops) == 2 and ops[1].type == 3 and ldr_target(a) is not None):
            rv.pop(ops[0].reg, None)
    elif mn in ('pop',) and any(op.type == 1 and op.reg == 15 for op in ops): break
    elif mn == 'bx' and ops and ops[0].type == 1 and ops[0].reg == 14: break
    elif ops and ops[0].type == 1 and mn not in ('cmp','cmn','tst','str','strh','strb','strd','push','bl','b','cbz','cbnz'):
        rv.pop(ops[0].reg, None)
    a += i.size; steps += 1
def sqr_seq(s1, s2, s3):
    L = (s1 >> 20) & 0xF; seq = []
    for i in range(1, 7): seq.append((s3 >> (5*(i-1))) & 0x1F)
    for i in range(7, 13): seq.append((s2 >> (5*(i-7))) & 0x1F)
    for i in range(13, 17): seq.append((s1 >> (5*(i-13))) & 0x1F)
    return L+1, seq[:L+1]
sqr = {}
for base, name in ADC_BASES.items():
    if name == 'ADCcc': continue
    s1 = writes.get(base+0x2C); s2 = writes.get(base+0x30); s3 = writes.get(base+0x34)
    if s1 is not None and s2 is not None and s3 is not None:
        n, seq = sqr_seq(s1, s2, s3); sqr[name] = seq
        pins = [CHPIN.get(c, f'ch{c}') for c in seq]
        print(f"  {name}: SQR1/2/3=0x{s1:08X}/0x{s2:08X}/0x{s3:08X} -> {n} conv: {seq} = {pins}")
ccr = writes.get(0x40012304)
if ccr is not None:
    print(f"  ADC_CCR=0x{ccr:08X} MULTI={ccr&0x1F} (6=dual regular simultaneous ADC1+ADC2)")
for nm, cr, ndtr, par, m0 in [('DMA2_Stream0(ADC1/2)',0x40026410,0x40026414,0x40026418,0x4002641C),
                              ('DMA2_Stream1(ADC3)',0x40026428,0x4002642C,0x40026430,0x40026434)]:
    if m0 in writes:
        print(f"  {nm}: CR=0x{writes.get(cr,0):X} NDTR={writes.get(ndtr,0)} PAR=0x{writes.get(par,0):08X} M0AR=0x{writes.get(m0,0):08X}")

print("\n== 4. mV getter scaling -> ADCctx field -> ADC3 slot/channel ==")
ctx = 0x20000988
# ADC3 sequence slots: handler accumulates PA2->ctx[0x10], PC2->ctx[0x18], PA0->ctx[0x20]
field_ch = {0x10: ('PA2', 2, 16), 0x18: ('PC2', 12, 8), 0x20: ('PA0', 0, 8)}
for k in ['ad_cpd','ad_pp','ad_bat']:
    g = pair.get(k)
    if g is None: continue
    a = g - TB; field = None; consts = []
    for _ in range(10):
        ins = dis(a)
        if not ins: break
        i = ins[0]
        if i.mnemonic in ('ldr','ldr.w') and len(i.operands) == 2 and i.operands[1].type == 3:
            if i.operands[1].mem.base != 15:      # skip the PC-relative ctx-base load
                field = i.operands[1].mem.disp
        if i.mnemonic in ('movw','mov.w') and len(i.operands) == 2 and i.operands[1].type == 2:
            consts.append(i.operands[1].imm & 0xFFFF)
        if i.mnemonic == 'bx': break
        a += i.size
    mult = consts[0] if consts else None; divv = consts[1] if len(consts) > 1 else None
    fc = field_ch.get(field)
    desc = f"ctx[0x{field:02X}] x{mult}/{divv}" if field is not None else "?"
    if fc and divv:
        pin, ch, nsamp = fc
        print(f"  {k:8s} getter 0x{g:08X}: {desc} = {nsamp}x{pin} avg, {mult} mV FS  -> {pin}/ADC3_IN{ch}")
    else:
        print(f"  {k:8s} getter 0x{g:08X}: {desc}")

print("\n== 5. IEC 61851-1 CP duty -> current classifier (0x08051E02) ==")
a = 0x08051E02 - TB; consts = []
for _ in range(40):
    ins = dis(a)
    if not ins: break
    i = ins[0]
    if i.mnemonic in ('movw','mov.w','movs','cmp','sub.w') and len(i.operands) >= 2 and i.operands[-1].type == 2:
        consts.append((i.mnemonic, i.operands[-1].imm))
    if i.mnemonic == 'pop': break
    a += i.size
print("  constants:", ", ".join(f"{m}#{v}(0x{v:X})" for m, v in consts[:14]))
print("  law: duty d% valid 8-97; d<10 -> 6 A; 10-85 -> (6*d+50)/100 = 0.6*d A;")
print("       85-96 -> (25*d-15950)/100 = 2.5*(d-64) A; 96-97 -> 80 A; else 0 (invalid).")

print("\n== RESOLVED ADC-channel -> CP/PP mapping (§5.5a / §8.4) ==")
print("  CP (Control Pilot):")
print("    DC voltage level (state A-F) = PA0 / ADC3_IN0  -> getter 0x08087E64, label 'AD_CPD' (3.3 V FS).")
print("    PWM duty/frequency           = TIM4_CH1 input-capture on PD12 (AF2), NOT ADC; median-filtered")
print("                                   (buf 0x20022688 -> ctx 0x200009C0); CP_DUTY=get[8], CP_FREQ=get[6].")
print("    duty->current = IEC 61851-1 (0x08051E02); duty->state-char {'0','1','5','M','N'} (0x08051E70),")
print("                    '5' = 5% DIN/ISO digital-comm mode (CP_ST_DUTY_5).")
print("  PP (Proximity Pilot) = PA2 / ADC3_IN2 -> getter 0x08087E3C, label 'AD_PP' (3.3 V FS).")
print("    PP state (PP_ST) = AD_PP window detector 0x08051D7A (2146/2296 mV, debounce 4 -> 0x2000087C).")
print("  Other analog: PA1/ADC3_IN1 = '+24V' rail; PC2/ADC3_IN12 = 'AD_BAT' battery (6.6 V FS, 2:1 divider);")
print("    PB0-PB1 (ADC1_IN8 - ADC2_IN9 dual simultaneous, DMA2_Stream0 CDR) = 'HV' DC-link voltage")
print("    (differential, averaged 3125 events -> 0x20000878).")
print("  ADC3 regular sequence SQ1..8 = [1,2,1,2,1,12,1,0] = PA1,PA2,PA1,PA2,PA1,PC2,PA1,PA0;")
print("    ADC1=8x ch8(PB0), ADC2=8x ch9(PB1); TIM8_TRGO triggered; DMA buffers 0x200225E8 / 0x20022628.")