#!/usr/bin/env python3
"""analyze106b.py — C013 codec-fidelity partials, session-layer + PVT unit + ETM (read-only RE).

Complements analyze106.py (grammar bodies). Resolves:
  G8  PVT unit enum A/V source        (PVT enc 0x0806A3AC full SM + CDReq ev11 0x0806BDDC builder)
  B2  CPDReq EnergyTransferMode value (ev0b 0x0806CEF0 reads [r4]; find app constant)
  G6  CD secondary interval set-site  (0x08039698 ctx+0x44 gated ctx+0x46==1; writers)
  G7  DIN skips states 4/5            (RX engine 0x080353B2 ServiceDiscovery case)
  G8  150s timeout compare site       (scan 0x08038xxx/0x08039xxx for cmp #0x249F0 / ctx+C)
  B2  SessionID negotiation           (SessionSetupRes header SID capture path)

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze106b.py'
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
def raw(addr, n, label):
    """Fixed-range walk, no stop at pop/bx (for multi-exit state machines)."""
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = ""
        if w is not None: ex = f"  ; =0x{w:08X}{tag(w)}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{ex}")
        a += i.size

if __name__ == '__main__':
    raw(0x0806A3AC, 130, 'PVT encoder full SM (unit source)')
    raw(0x0806BDDC, 150, 'CDReq ev11 encoder (PVT unit constants)')
    raw(0x08039660, 90, 'G6 CD secondary cadence region (ctx+0x44/0x46)')
    raw(0x080353B2, 60, 'G7 RX engine head (ServiceDiscovery dispatch)')
    # G8: scan the poll region for the 150000 (0x249F0) compare / ctx+C (offset 0xC) loads.
    print("\n== G8 150s compare scan: movw #0x49f0 / #0x249f0 + cmp in 0x08038000..0x0803A000 ==")
    a = 0x08038000 - TB
    end = 0x0803A000 - TB
    while a < end:
        ins = dis(a)
        if not ins: a += 2; continue
        i = ins[0]
        if i.mnemonic in ('movw', 'movt', 'cmp', 'cmp.w') and ('0x49f0' in i.op_str or '0x249f0' in i.op_str or '#0xc]' in i.op_str):
            w = pool(a); ex = f"  ; =0x{w:08X}" if w is not None else ""
            print(f"  0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{ex}")
        a += i.size