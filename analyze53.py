#!/usr/bin/env python3
"""Locate the UPG update orchestration via its strings (indirect .rodata pointer
tables — analyze48 showed no direct xrefs). Finds pointer-table entries for the
UPG filenames / update log strings, then LDR-literal/ADR/movw-movt code xrefs to
those tables (or direct string-address loads), and disassembles around each site
(capstone, skip-bad-halfword). Reveals the update flow: f_open/f_read, any
checksum/verify step, flash-writer indirect call, reset.
Usage: python3 analyze53.py firmware.bin [> update53.txt]"""
import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

STR = {0x02ff56: "'%s' file Open for read Error", 0x02ff76: "'%s' has been updated",
       0x02ffee: "Write flash error[%u]", 0x03001a: "[%t]UPGRADE Finished",
       0x030102: "BOOT_CCS2CHADEMO_1.UPG", 0x03011a: "MAIN_CCS2CHADEMO_1.UPG",
       0x030132: "MAIN_CCS2CHADEMO_1_ID6.UPG",
       0x030d72: "UPGRADE:[%u]..."}
RUN = {BASE + o: nm for o, nm in STR.items()}

print("== pointer-table entries (u32 LE runtime string addresses) ==")
ptr_sites = []
for R, nm in RUN.items():
    pat = struct.pack('<I', R)
    i = dec.find(pat); found = []
    while i != -1:
        found.append(i); i = dec.find(pat, i + 1)
    print(f"  {nm}: runtime 0x{R:08X} -> {[hex(f) for f in found] if found else 'none'}")
    ptr_sites += found

windows = [(p - 256, p + 256) for p in ptr_sites]
def in_window(t):
    return any(a <= t <= b for a, b in windows)

def imm16(h1, h2): return (((h1 >> 4) & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)

print("\n== code xrefs (LDR-literal/ADR to pointer tables, or direct string loads) ==")
sites = []
last = {}
for a in range(0x400, n - 4, 2):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 & 0xFBF0) == 0xF240: last[(h2 >> 8) & 0xF] = (a, imm16(h1, h2))
    elif (h1 & 0xFBF0) == 0xF2C0:
        rd = (h2 >> 8) & 0xF
        if rd in last:
            pa, lo = last[rd]; v = (imm16(h1, h2) << 16) | lo
            if v in RUN: sites.append((pa, f"movw/movt direct {RUN[v]}"))
            del last[rd]
    if (h1 & 0xFF7F) == 0xF85F:
        u = (h1 >> 7) & 1
        t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
        if 0 <= t < n - 3:
            v = struct.unpack_from('<I', dec, t)[0]
            if v in RUN: sites.append((a, f"ldrT2 direct {RUN[v]}"))
            elif in_window(t): sites.append((a, f"ldrT2 -> table f+0x{t:06x}"))
    if (h1 & 0xF800) == 0x4800:
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if t < n - 3:
            v = struct.unpack_from('<I', dec, t)[0]
            if v in RUN: sites.append((a, f"ldrT1 direct {RUN[v]}"))
            elif in_window(t): sites.append((a, f"ldrT1 -> table f+0x{t:06x}"))
    if (h1 & 0xF800) == 0xA000:
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if in_window(t): sites.append((a, f"adrT1 -> table f+0x{t:06x}"))
    if (h1 & 0xFBFF) in (0xF20F, 0xF2AF):
        imm = (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
        t = ((a + 4) & ~3) + (imm if (h1 & 0xFBFF) == 0xF20F else -imm)
        if 0 <= t < n and in_window(t): sites.append((a, f"adrT3 -> table f+0x{t:06x}"))

for a, why in sites: print(f"  f+0x{a:06x} (0x{BASE+a:08X}): {why}")
print(f"total sites: {len(sites)}")

def disasm_region(start, length, label):
    print(f"\n--- disasm {label}: f+0x{start:06x}..f+0x{start+length:06x} ---")
    a = start; end = start + length
    while a < end:
        chunk = dec[a:min(a + 2, end)]
        if len(chunk) < 2: break
        ins = list(md.disasm(dec[a:a + 4], BASE + a, count=1))
        if ins:
            i = ins[0]
            print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}")
            a += i.size
        else:
            print(f"  0x{BASE+a:08x} f+0x{a:06x}: .hword 0x{struct.unpack_from('<H', dec, a)[0]:04x}  (bad)")
            a += 2

seen = set()
for a, why in sites:
    start = max(0x400, (a - 160) & ~1)
    key = start // 512
    if key in seen: continue
    seen.add(key)
    disasm_region(start, 768, why)
