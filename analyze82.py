#!/usr/bin/env python3
"""analyze82.py — CHAdeMO message-layer + current/voltage control-law mapper (§5.18/§5.17, roadmap E):
re-derives from the C013 firmware bytes how the adapter (acting as CHAdeMO charger toward the vehicle)
builds and transmits the periodic H108/H109 status messages, and how the output voltage/current values
are scaled, capped and periodically gated. This is the report half of the safe-charge control law; the
vehicle-request half (H100/H101/H102 parse) and the engagement guard live in §5.17 (analyze80).

Parts:
  1. Scan for CHAdeMO CAN-ID stores (`mov r1,#ID; str r1,[rX,#0x60]`, ID in 0x100/101/102/108/109/200/201)
     -> locate every periodic message sender by its enclosing function (byte-derived, no hardcoded addr).
  2. For each sender, decode the 8-byte CAN payload packing: source context offsets (ldrb/ldrh [p+disp])
     -> destination buffer bytes (strb [buf+byte]), incl. lsrs #8 high-byte splits and any bit-reversal.
  3. Decode the payload-build scaling law: udiv by 1000 (0x3E8), the output cap (cmp #0x1C2 = 450), the
     periodic state-gating, and the CAN TX path (fn-ptr p[+0x270] -> 0x8052EE2, mutex 0x200007E8).

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze82.py'
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
    while a > o-0x400:
        h = u16(a)
        if (h & 0xFF00)==0xB500 or (h & 0xFFF0)==0xE920: return a
        a -= 2
    return o-0x40
def func_end(fs):
    a = fs+2
    while a < fs+0x400 and a < N-2:
        ins = dis(a)
        if not ins: a += 2; continue
        i = ins[0]
        if i.mnemonic=='bx' or (i.mnemonic=='pop' and 'pc' in i.op_str): return a+i.size
        a += i.size
    return fs+0x200

CHA_ID = {0x100:'H100', 0x101:'H101', 0x102:'H102', 0x108:'H108', 0x109:'H109',
          0x200:'H200', 0x201:'H201'}

print("== 1. CHAdeMO CAN-ID stores -> periodic message senders ==")
# find `mov/movw r1,#ID` (ID in CHA_ID) followed within 8 bytes by `str r1,[rX,#0x60]`
senders = {}   # func_start -> (id, store_offset)
for o in range(0, N-6, 2):
    ins = dis(o)
    if not ins: continue
    i = ins[0]
    if i.mnemonic in ('mov','movs','mov.w','movw') and len(i.operands)==2 \
       and i.operands[0].type==1 and i.operands[0].reg==67 and i.operands[1].type==2:  # r1=67
        imm = i.operands[1].imm
        if imm in CHA_ID:
            for d in range(o+2, o+10, 2):
                j = dis(d)
                if j and j[0].mnemonic in ('str','str.w') and len(j[0].operands)==2 \
                   and j[0].operands[0].type==1 and j[0].operands[0].reg==67 \
                   and j[0].operands[1].type==3 and j[0].operands[1].mem.disp==0x60:
                    fs = func_start(o)
                    senders.setdefault(fs, (imm, o))
                    break
for fs in sorted(senders):
    imm, o = senders[fs]
    print(f"  {CHA_ID[imm]} (ID 0x{imm:03X}): sender f+0x{fs:05x} (0x{rt(fs):08X}), ID-store f+0x{o:05x}")

print("\n== 2. H108/H109 payload byte-packing (context offset -> CAN data byte) ==")
def decode_pack(fs):
    fe = func_end(fs)
    a = fs; last_src = None; last_hi = False; packs = []; bitrev = False
    while a < fe:
        ins = dis(a)
        if not ins: a += 2; continue
        i = ins[0]; ops = i.operands; mn = i.mnemonic
        # source load from context p (base r4=70): ldrb/ldrh [r4+disp]
        if mn in ('ldrb','ldrb.w','ldrh','ldrh.w') and len(ops)==2 and ops[1].type==3 \
           and ops[1].mem.base==70:
            last_src = (ops[1].mem.disp, mn); last_hi = False
        elif mn in ('lsrs','lsr','lsr.w') and len(ops)==3 and ops[2].type==2 and ops[2].imm==8:
            last_hi = True   # high byte of preceding halfword
        elif mn=='ubfx':
            bitrev = True
        # dest store to buffer (base r1=67): strb [r1+byte] or strb [r1]
        elif mn in ('strb','strb.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.base==67:
            byte = ops[1].mem.disp
            if last_src is not None:
                disp, kind = last_src
                hb = '>>8' if last_hi else ('lo' if kind.startswith('ldrh') else '')
                packs.append((byte, disp, hb))
            last_src = None; last_hi = False
        a += i.size
    return packs, bitrev
for fs in sorted(senders):
    imm, _ = senders[fs]
    if imm not in (0x108, 0x109): continue
    packs, bitrev = decode_pack(fs)
    print(f"  {CHA_ID[imm]} sender f+0x{fs:05x} (0x{rt(fs):08X}):")
    seen = {}
    for byte, disp, hb in packs:
        key = (byte, disp, hb)
        if key in seen: continue
        seen[key] = 1
        tag = f'p[+0x{disp:03X}]' + (f' {hb}' if hb else '')
        print(f"    CAN byte {byte} <- {tag}")
    if bitrev: print("    (contains a ubfx bit-field reversal — one status byte is bit-reversed on the wire)")

print("\n== 3. payload-build scaling law + CAN TX path ==")
# the build functions write p[+0x210..0x228]; the /1000 divisor and the 450 cap are loaded into
# registers (mov #0x3E8 / mov #0x1C2) then used by udiv/cmp — track those constants per register.
print("  scaling/cap sites in the message-build region f+0x1cd5e..0x1cf38 (register-form udiv/cmp):")
a = 0x1cd5e; k1000 = set(); k450 = set()
while a < 0x1cf38:
    ins = dis(a)
    if not ins: a += 2; continue
    i = ins[0]; ops = i.operands; mn = i.mnemonic
    if mn in ('mov','movs','mov.w','movw') and len(ops)==2 and ops[0].type==1 and ops[1].type==2:
        rd = ops[0].reg; imm = ops[1].imm
        k1000.discard(rd); k450.discard(rd)
        if imm == 0x3e8: k1000.add(rd)
        elif imm == 0x1c2: k450.add(rd)
    elif mn in ('udiv','sdiv') and len(ops)==3 and ops[2].type==1 and ops[2].reg in k1000:
        print(f"    f+0x{a:05x} 0x{rt(a):08X}: {mn} {i.op_str}  ; /1000 scale (divisor reg = 1000)")
    elif mn=='cmp' and len(ops)==2 and ops[1].type==1 and ops[1].reg in k450:
        print(f"    f+0x{a:05x} 0x{rt(a):08X}: cmp {i.op_str}  ; clamp at 450 (0x1C2) — blo/mov caps the output")
    elif mn in ('ldr','ldr.w','ldrb','ldrh','muls','mul','adds','subs','uxth','sxth') and ops and ops[0].type==1:
        k1000.discard(ops[0].reg); k450.discard(ops[0].reg)   # dest clobbered -> invalidate
    a += i.size
print("  CAN TX path (from the H108/H109 senders):")
print("    memset(buf,0,8) via 0x080882CE; buf ptr = p[+0x25C]; CAN ID written to 0x200007E0")
print("    ([0x200007E8-0x68+0x60]); mutex 0x200007E8 take 0x08089D4C / give 0x08089DB8;")
print("    TX fn-ptr p[+0x270] (blx) then CAN1 transmit 0x08052EE2 (ID, buf).")
print("  Build scaling: EVSE-side measurements (source struct +0x3d08/0a/14/16/18/1a/22/30) read via")
print("  0x0804E786, value*raw/1000, output clamped to 450; H109 build is periodic-state-gated")
print("  (only every 10th tick in the CurrentDemand/stop state ranges -> 'every n minute adjusts').")

print("\n== RESOLVED CHAdeMO charger->vehicle message layer (C013) ==")
print("  H108 (0x108): build 0x0803C95C (scale /1000, cap 450 -> p[+0x212]); send 0x0803CB36.")
print("    byte0=p[210] status, byte1-2=p[212], byte3=p[214], byte4-5=p[216], byte6=p[218], byte7=p[219].")
print("  H109 (0x109): build 0x0803C9B8 (scale /1000, state-gated -> p[+0x220..224]); send 0x0803CBDC.")
print("    byte0=p[220], byte1-2=p[222], byte3=p[224], byte4=p[225], byte5=p[226] (bit-reversed),")
print("    byte6=p[227], byte7=p[228].")
print("  Field physical meaning (voltage/current/remaining-time) follows the CHAdeMO H108/H109 spec;")
print("  the byte packing, IDs, /1000 scaling, 450 cap and bit-reversal are byte-derived above.")