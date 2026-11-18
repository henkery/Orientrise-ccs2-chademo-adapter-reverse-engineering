#!/usr/bin/env python3
"""Diff Orientrise MAINARM firmware revisions C009 (firmware.bin) vs C013.

Both are XOR-2B23-decoded .UPG app images (base 0x08020000). Compares:
  - $$ header (version / build date / model)
  - unique printable strings: added / removed / common-offset-shift
  - byte-level change regions mapped to STM32F4 flash sectors
  - the encrypted prefix block and the F$K$N$T$2005 ID block
Read-only.

Usage: nix-shell -p python3 --run 'python3 analyze41.py firmware.bin <decoded_c013.bin>'
"""
import sys, re, struct, collections

a = open(sys.argv[1], 'rb').read()   # C009
b = open(sys.argv[2], 'rb').read()   # C013
BASE = 0x08020000

def header(d):
    return [l.decode('ascii', 'replace') for l in d[:0x58].split(b'\r\n') if l.strip(b'\x00+')]

print("=== HEADERS ===")
print(f"  C009 ({len(a)} B): {header(a)}")
print(f"  C013 ({len(b)} B): {header(b)}")
print(f"  size delta: {len(b)-len(a):+d} B")

def strings(d):
    out = {}
    for m in re.finditer(rb'[\x20-\x7e]{6,}', d):
        s = m.group().decode('latin1')
        out.setdefault(s, m.start())
    return out

sa, sb = strings(a), strings(b)
added = sorted(set(sb) - set(sa), key=lambda s: sb[s])
removed = sorted(set(sa) - set(sb), key=lambda s: sa[s])
common = set(sa) & set(sb)
print(f"\n=== STRINGS ===  C009={len(sa)}  C013={len(sb)}  common={len(common)}  "
      f"added={len(added)}  removed={len(removed)}")

print(f"\n--- ADDED in C013 ({len(added)}) ---")
for s in added:
    print(f"  c013+0x{sb[s]:06x}  {s}")
print(f"\n--- REMOVED from C009 ({len(removed)}) ---")
for s in removed:
    print(f"  c009+0x{sa[s]:06x}  {s}")

shifts = collections.Counter(sb[s] - sa[s] for s in common)
print("\n--- common-string offset shifts (delta -> count) ---")
for d, c in shifts.most_common(12):
    print(f"  {d:+8d} (0x{d & 0xffffffff:x})  x{c}")

# ---- byte-level change regions ----
print("\n=== BYTE CHANGE REGIONS (min run 16 B, gap-bridged 32 B) ===")
n = min(len(a), len(b))
diff = [i for i in range(n) if a[i] != b[i]]
regions = []
if diff:
    start = prev = diff[0]
    for i in diff[1:]:
        if i - prev > 32:
            regions.append((start, prev + 1)); start = i
        prev = i
    regions.append((start, prev + 1))
SECT = [(0, 0x4000, '0'), (0x4000, 0x8000, '1'), (0x8000, 0xC000, '2'),
        (0xC000, 0x10000, '3'), (0x10000, 0x20000, '4'), (0x20000, 0x40000, '5'),
        (0x40000, 0x60000, '6'), (0x60000, 0x80000, '7'), (0x80000, 0xA0000, '8'),
        (0xA0000, 0xC0000, '9'), (0xC0000, 0xE0000, '10'), (0xE0000, 0x100000, '11')]
def sect(off):
    for lo, hi, name in SECT:
        if lo <= off < hi:
            return name
    return '?'
tot = 0
for lo, hi in regions:
    if hi - lo < 16:
        continue
    tot += hi - lo
    print(f"  f+0x{lo:06x}..0x{hi:06x} ({hi-lo:6d} B)  virt 0x{BASE+lo:08x}  sector {sect(lo)}")
print(f"  total changed (>=16B runs): {tot} B over {len([r for r in regions if r[1]-r[0]>=16])} regions")
if len(b) > len(a):
    print(f"  C013 tail beyond C009 end: f+0x{len(a):06x}..0x{len(b):06x} ({len(b)-len(a)} B)")

# ---- prefix block + ID block ----
print("\n=== PREFIX BLOCK f+0x58..0x400 (encrypted) ===")
pa, pb = a[0x58:0x400], b[0x58:0x400]
print(f"  identical: {pa == pb}  (C009 {len(pa)} B vs C013 {len(pb)} B)")
print(f"  C009 footer tail: {a[0x3e0:0x400].hex(' ')}")
print(f"  C013 footer tail: {b[0x3e0:0x400].hex(' ')}")

print("\n=== F$K$N$T$2005 ID BLOCK ===")
for tag, d in (('C009', a), ('C013', b)):
    i = d.find(b'F$K$N$T$2005')
    if i >= 0:
        chunk = d[i:i + 128]
        printable = re.findall(rb'[\x20-\x7e]{4,}', chunk)
        print(f"  {tag} @ f+0x{i:06x}: " + b' | '.join(printable).decode('latin1'))
    else:
        print(f"  {tag}: not found")