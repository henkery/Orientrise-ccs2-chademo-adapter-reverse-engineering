#!/usr/bin/env python3
"""analyze106c.py — C013 codec-fidelity: SessionSetupRes SID path + PVT unit / ETM app constants.

  B2  SessionSetupRes ev41 0x08062B1E — confirm SessionID is header-only (gid 0x6c), body has
      EVSEID + optional timestamp; the negotiated SID rides the DIN header of every Res.
  G8  PVT unit enum A/V + CPDReq EnergyTransferMode — locate the app struct builder that writes
      the PVT unit byte (struct+1) and the CPDReq ETM byte (struct+0). Scan the CD/CPD Req builder
      region for the unit/ETM immediates.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze106c.py'
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
def raw(addr, n, label):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = f"  ; =0x{w:08X}" if w is not None else ""
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{ex}")
        a += i.size

if __name__ == '__main__':
    raw(0x08062B1E, 90, 'SessionSetupRes ev41 decoder (SID header-only confirm)')
    # The CDReq/CPDReq app builder writes PVT unit bytes + ETM. The TX encode wrapper 0x08034C30
    # (called by the G6 CD send) takes the struct; dump its head to find the builder upstream.
    raw(0x08034C30, 70, 'CD/CPD Req TX encode wrapper (struct builder trace)')