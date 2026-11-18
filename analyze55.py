#!/usr/bin/env python3
"""Find how the UPG update strings are ACTUALLY referenced. analyze53 found zero
absolute pointers / movw-movt loads of their runtime addresses — so the update
code must use PC-relative (ADR/ADD) or base+offset addressing, or the strings.txt
offsets are stale. Verify offsets in-image first, then scan: u32 pointers (any
alignment), ADR T1/T3 to the strings, LDR-literal/movw-movt loads of any value
inside the string cluster (base pointers), and u16 offset-table patterns.
Usage: python3 analyze55.py firmware.bin [> update55.txt]"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

WANT = [b"'%s' file Open for read Error", b"'%s' has been updated", b"Write flash error[%u]",
        b"[%t]UPGRADE Finished", b"BOOT_CCS2CHADEMO_1.UPG", b"MAIN_CCS2CHADEMO_1.UPG",
        b"MAIN_CCS2CHADEMO_1_ID6.UPG", b"UPGRADE:[%u]"]
print("== locate strings in-image ==")
offs = {}
for s in WANT:
    i = dec.find(s)
    offs[s] = i
    print(f"  {s.decode()!r}: f+0x{i:06x} (runtime 0x{BASE+i:08X})" if i != -1 else f"  {s!r}: NOT FOUND")
claimed = {0x02ff56: WANT[0], 0x02ff76: WANT[1], 0x02ffee: WANT[2], 0x03001a: WANT[3],
           0x030102: WANT[4], 0x03011a: WANT[5], 0x030132: WANT[6], 0x030d72: WANT[7]}
for o, s in claimed.items():
    actual = dec[o:o + len(s)]
    if actual != s: print(f"  STALE strings.txt offset 0x{o:06x}: expected {s!r}, found {actual!r}")

lo = min(o for o in offs.values() if o != -1); hi = max(o for o in offs.values() if o != -1)
cluster = (lo - 0x2000, hi + 0x2000)
print(f"\ncluster window: f+0x{cluster[0]:06x}..f+0x{cluster[1]:06x} (runtime 0x{BASE+cluster[0]:08X}..0x{BASE+cluster[1]:08X})")
RUN = {BASE + i: s for s, i in offs.items() if i != -1}

print("\n== u32 LE pointers to exact string runtime addresses (any alignment) ==")
for R, s in RUN.items():
    pat = struct.pack('<I', R); i = dec.find(pat); found = []
    while i != -1:
        found.append(i); i = dec.find(pat, i + 1)
    print(f"  {s.decode()!r}: {[hex(f) for f in found] if found else 'none'}")

print("\n== u32 LE values pointing ANYWHERE inside the cluster (base/table pointers) ==")
hits = []
for a in range(0, n - 3):
    v = struct.unpack_from('<I', dec, a)[0]
    if BASE + cluster[0] <= v <= BASE + cluster[1]:
        hits.append((a, v))
for a, v in hits[:60]:
    print(f"  f+0x{a:06x} ({'4B' if a%4==0 else '2B' if a%2==0 else 'odd'}): 0x{v:08X} -> f+0x{v-BASE:06x}")
print(f"  total: {len(hits)}")

def imm16(h1, h2): return (((h1 >> 4) & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)

print("\n== code scans: ADR to strings; LDR-lit/movw-movt of cluster values ==")
sites = []
last = {}
for a in range(0x400, n - 4, 2):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 & 0xFBF0) == 0xF240: last[(h2 >> 8) & 0xF] = (a, imm16(h1, h2))
    elif (h1 & 0xFBF0) == 0xF2C0:
        rd = (h2 >> 8) & 0xF
        if rd in last:
            pa, l = last[rd]; v = (imm16(h1, h2) << 16) | l
            if v in RUN: sites.append((pa, f"movw/movt EXACT {RUN[v].decode()!r}"))
            elif BASE + cluster[0] <= v <= BASE + cluster[1]: sites.append((pa, f"movw/movt cluster base 0x{v:08X}"))
            del last[rd]
    if (h1 & 0xFF7F) == 0xF85F:
        u = (h1 >> 7) & 1
        t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
        if 0 <= t < n - 3:
            v = struct.unpack_from('<I', dec, t)[0]
            if v in RUN: sites.append((a, f"ldrT2 EXACT {RUN[v].decode()!r}"))
            elif BASE + cluster[0] <= v <= BASE + cluster[1]: sites.append((a, f"ldrT2 cluster base 0x{v:08X} (pool f+0x{t:06x})"))
    if (h1 & 0xF800) == 0x4800:
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if t < n - 3:
            v = struct.unpack_from('<I', dec, t)[0]
            if v in RUN: sites.append((a, f"ldrT1 EXACT {RUN[v].decode()!r}"))
            elif BASE + cluster[0] <= v <= BASE + cluster[1]: sites.append((a, f"ldrT1 cluster base 0x{v:08X} (pool f+0x{t:06x})"))
    if (h1 & 0xF800) == 0xA000:
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if BASE + t in RUN: sites.append((a, f"adrT1 EXACT {RUN[BASE+t].decode()!r}"))
    if (h1 & 0xFBFF) in (0xF20F, 0xF2AF):
        imm = (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
        t = ((a + 4) & ~3) + (imm if (h1 & 0xFBFF) == 0xF20F else -imm)
        if 0 <= t < n and BASE + t in RUN: sites.append((a, f"adrT3 EXACT {RUN[BASE+t].decode()!r}"))

for a, why in sites: print(f"  f+0x{a:06x} (0x{BASE+a:08X}): {why}")
print(f"total sites: {len(sites)}")

def disasm_region(start, length, label):
    print(f"\n--- disasm {label}: f+0x{start:06x}..f+0x{start+length:06x} ---")
    a = start; end = min(start + length, n - 4)
    while a < end:
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
    start = max(0x400, (a - 192) & ~1)
    key = start // 640
    if key in seen: continue
    seen.add(key)
    disasm_region(start, 896, why)
