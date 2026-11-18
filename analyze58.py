#!/usr/bin/env python3
"""Disassemble the usbdisk state-2 UPDATE WORKER at f+0x04FDFE (called from the
process loop @0x0301D2) and summarize its BL callees. The usbdisk module's literal
pools are runtime-relocated (analyze57), so trace via static BL targets instead.
Goal: locate f_open/f_read/f_write/f_close + the flash-write call + a safe hook
point for the bootloader dump. Also disassemble the two exit-path callees.
Usage: python3 analyze58.py firmware.bin [> update58.txt]"""
import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

def bl_target(a):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 >> 11) != 0x1E or (h2 & 0xD000) != 0xD000: return None
    S = (h1 >> 10) & 1; imm10 = h1 & 0x3FF; J1 = (h2 >> 13) & 1; J2 = (h2 >> 11) & 1; imm11 = h2 & 0x7FF
    I1 = 1 - ((J1 ^ S) & 1); I2 = 1 - ((J2 ^ S) & 1)
    off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    if off & (1 << 24): off -= 1 << 25
    return (a + 4) + off

def disasm(start, end, label, show_pool=True):
    print(f"\n--- {label}: f+0x{start:06x}..f+0x{end:06x} ---")
    a = start; callees = collections.Counter()
    while a < end:
        ins = list(md.disasm(dec[a:a + 4], BASE + a, count=1))
        if not ins:
            print(f"  f+0x{a:06x}: .hword 0x{struct.unpack_from('<H', dec, a)[0]:04x} (bad)"); a += 2; continue
        i = ins[0]; h1 = struct.unpack_from('<H', dec, a)[0]; note = ''
        if i.mnemonic == 'bl':
            t = bl_target(a)
            if t is not None:
                callees[t] += 1; note = f"   -> f+0x{t:06x}"
        elif (h1 & 0xFF7F) == 0xF85F and i.size == 4:
            h2 = struct.unpack_from('<H', dec, a + 2)[0]; u = (h1 >> 7) & 1
            t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
            if 0 <= t < n - 3 and show_pool:
                w = struct.unpack_from('<I', dec, t)[0]
                note = f"   [pool f+0x{t:06x}=0x{w:08X}]"
        elif (h1 & 0xF800) == 0x4800 and show_pool:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            if t < n - 3:
                w = struct.unpack_from('<I', dec, t)[0]
                note = f"   [pool f+0x{t:06x}=0x{w:08X}]"
        elif (h1 & 0xF800) == 0xA000:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            s = dec[t:t + 24].split(b'\x00')[0]
            pr = s.decode('ascii', 'replace') if len(s) >= 3 and all(32 <= c < 127 for c in s) else ''
            note = f"   [adr f+0x{t:06x} {pr!r}]"
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}{note}")
        a += i.size
    print(f"  BL callees: " + ", ".join(f"f+0x{t:06x}(x{c})" for t, c in sorted(callees.items())))
    return callees

c1 = disasm(0x04FDFE, 0x050200, "update worker (state 2)")
disasm(0x050B62, 0x050B9C, "exit callee 0x050B62")
disasm(0x050B9C, 0x050C40, "exit callee 0x050B9C")
