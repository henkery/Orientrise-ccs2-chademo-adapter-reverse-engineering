#!/usr/bin/env python3
"""analyze89.py — H102 output-current control law, byte-exact (§5.21 E, supersedes the analyze85 sketch).

Re-derives from the C013 firmware bytes the state-30 CurrentDemand output-current setpoint computation
(the block at 0x08044D42–0x08044DBC) and the scaling converter 0x0804E786. This CORRECTS the analyze85
sketch ("setpara(selector 4) copies struct[+0x44]->[+0x40]"): in C013 the setpara dispatcher 0x0804E884
is a validation stub (cbz r0/r1; cmp r2,#0..5 all branch to a common return), and the real current control
is computed INLINE in state-30, writing the shared output context 0x20000780 at +0x16/+0x18 (current
setpoint), +0x1a (EVSE max-current cap), +0x1c/+0x1e (target voltage).

The law (min/cap, /1000 scaling):
  cap      = scale(EVSE_raw[0x3D20], converter(byte[0x3D22]))          -> ctx[+0x1a]
  avail    = scale(EVSE_raw[[sp+0x48]], converter(byte))
  setpoint = min(H102.ChargingCurrentRequest[p+0x1dc], avail)          -> ctx[+0x18] (uncapped)
  if setpoint > cap && cap != 0: setpoint = cap                        -> ctx[+0x16] (capped)
  target_v = H102.TargetBatteryVoltage[p+0x1da]                        -> ctx[+0x1e] (uncapped)
  if p[+0x216] != 0 && p[+0x216] <= target_v: target_v = p[+0x216]     -> ctx[+0x1c] (capped)
  scale(raw, factor) = (uint16)((uint32)raw * converter(factor) / 1000)   (muls + udiv #0x3e8)
  converter(code)    = (code < 7) ? code : 0xFF   (sxtb + signed blt; 0x0804E786)
Zero-skip: a zero min(request,avail) skips the current stores (cbz -> keep previous); a zero target
voltage skips the voltage stores. cap is written unconditionally.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze89.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
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
def dump(addr, n, label):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = ""
        if w is not None:
            tag = (" FLASH" if 0x08000000 <= w < 0x08100000 else
                   " RAM" if 0x20000000 <= w < 0x20030000 else "")
            ex = f"  ; =0x{w:08X}{tag}"
        hl = " <<<" if (i.mnemonic in ('muls', 'udiv', 'sdiv') or '#0x1a]' in i.op_str
                        or '#0x16]' in i.op_str or '#0x1c]' in i.op_str) else ""
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{ex}{hl}")
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break

print("################ H102 -> OUTPUT-CURRENT CONTROL LAW (§5.21 E, byte-exact) ################")
# Anchor: the CurrentDemand block loads the EVSE max-current range code via movw #0x3d22, then the
# shared output context 0x20000780 and stores the cap at [+0x1a]. Find the movw #0x3d22 site whose
# forward window contains a 0x20000780 load + strh [r8,#0x1a].
anchor = None
for o in range(0, N-4, 2):
    ins = dis(o)
    if not ins: continue
    i = ins[0]
    if i.mnemonic == 'movw' and i.operands and i.operands[-1].type == 2 and i.operands[-1].imm == 0x3d22:
        a = o; has_ctx = False; has_cap = False
        for _ in range(20):
            j = dis(a)
            if not j: break
            if pool(a) == 0x20000780: has_ctx = True
            if j[0].mnemonic in ('strh', 'strh.w') and '#0x1a]' in j[0].op_str: has_cap = True
            a += j[0].size
        if has_ctx and has_cap:
            anchor = o; break
if anchor is None:
    print("  !! CurrentDemand movw #0x3d22 anchor not found"); raise SystemExit(1)
print(f"  CurrentDemand block anchor (movw #0x3d22): f+0x{anchor:05x} (0x{rt(anchor):08X})")
dump(rt(anchor) - 4, 50, "state-30 CurrentDemand output-current setpoint block")

print("\n== scaling converter (the /1000 multiplier) ==")
dump(0x0804E786, 8, "converter 0x0804E786")
print("  law: converter(code) = (code < 7) ? code : 0xFF  (sxtb sign-extend, then signed blt).")
print("       Codes 0..6 pass through as the multiplier; >=7 clamp to 0xFF (255). Used as the factor")
print("       in scale(raw,factor) = raw*converter(factor)/1000 (muls + udiv #0x3e8, strh low16).")

print("\n== setpara dispatcher 0x0804E884 (C013 = validation stub, NOT the current-control path) ==")
dump(0x0804E884, 14, "setpara dispatcher")
print("  cbz r0/r1 -> ret 0; cmp r2,#0..5 all branch to a common return -> no per-selector work in C013.")
print("  This CORRECTS analyze85's 'setpara(4) copies [+0x44]->[+0x40]' sketch: the real setpoint law is")
print("  the inline state-30 block above, writing 0x20000780 +0x16/+0x18/+0x1a/+0x1c/+0x1e.")

print("\n== RESOLVED H102 current-control law (C013, §5.21 E) ==")
print("  Output context 0x20000780 (shared CAN/charge ctx): +0x16 capped current setpoint, +0x18 uncapped")
print("  min(request,avail), +0x1a EVSE max-current cap, +0x1c capped target voltage, +0x1e uncapped target.")
print("  setpoint = min(H102.ChargingCurrentRequest, EVSE avail), then capped by EVSE max (cap!=0).")
print("  target_v = min(H102.TargetBatteryVoltage, p[+0x216] limit). EVSE-side raw measurements come from")
print("  the CCS2 PLC/DIN subsystem (+0x3D20/0x3D22 max, [sp+0x48] present); /1000 + converter scaling.")
print("  Overcurrent protection: never command more than the EVSE can deliver or the vehicle requests.")
print("  Replicated INERT in custom_fw/src/current_ctrl.c (shadow setpoint, no power drive); host-tested")
print("  in custom_fw/test_current_ctrl.c (converter/scale/min/cap/zero-skip + EVSE-stub safety).")