#!/usr/bin/env python3
"""analyze106.py — C013 DIN codec-fidelity partials decoder (read-only RE).

Resolves the CCS2_GAPS §5 priority-1 codec [?] items byte-exact from the C013 decoded image:
  G8  CDRes optional max-limit choice chain   (ev12 decoder 0x0806471E, states 0x23/24/25)
  G8  PVT unit enum A/V                      (PVT enc 0x0806A3AC / dec 0x08062070 + unit source)
  B2  SessionSetupReq ev40 prologue gates    (0x0806ABEA)
  B2  PreChargeReq ev2f inter-field gates    (0x0806B4DE)
  B2  CPDReq ev0b / DC_EVChargeParameter ev13 gates + EnergyTransferMode DC enum (0x0806CEF0/CC3A)
  B2  ServiceDiscoveryRes ev3d list sub-grammars (0x08063370, ServiceList ev39)
  B2  CPDRes ev0c AC-sched choice            (0x08065BFC, state 0x74)

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze106.py'
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
        if w is not None: ex = f"  ; =0x{w:08X}{tag(w)}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{ex}")
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break
    return a

if __name__ == '__main__':
    dump(0x08062070, 70, 'PVT decoder (unit choice/enum)')
    dump(0x0806A3AC, 70, 'PVT encoder (unit choice/enum)')
    dump(0x0806471E, 420, 'CDRes ev12 decoder (optional max-limit choice chain)')
    dump(0x0806ABEA, 130, 'SessionSetupReq ev40 encoder (prologue gates)')
    dump(0x0806B4DE, 170, 'PreChargeReq ev2f encoder (inter-field gates)')
    dump(0x0806CEF0, 130, 'CPDReq ev0b encoder (EnergyTransferMode + gates)')
    dump(0x0806CC3A, 220, 'DC_EVChargeParameter ev13 encoder (PVT unit source + gates)')
    dump(0x08063370, 320, 'ServiceDiscoveryRes ev3d decoder (list sub-grammars)')
    dump(0x08065BFC, 320, 'CPDRes ev0c decoder (AC-sched choice state 0x74)')