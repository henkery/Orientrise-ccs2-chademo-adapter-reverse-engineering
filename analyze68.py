#!/usr/bin/env python3
"""Parse the ARM __scatterload region table (file 0x48A, referenced by adr@0x45E) to
learn (a) which code/data regions are RELOCATED to RAM (exec addr 0x200xxxxx/0x100xxxxx)
vs run in place in flash (0x080xxxxx), and (b) the .bss/ZI + stack layout (free RAM).
Each entry = {r0=load, r1=exec, r2=size, r3=init_fn}; init_fn offset-encoded (bit0=1 =>
func = (tablebase-1) - r3). The copy/zero/decompress helpers are at 0x4EC/0x50A/0x494.
Usage: nix-shell -p python3 --run 'python3 analyze68.py firmware.bin'
"""
import sys, struct
dec = open(sys.argv[1], 'rb').read(); BASE = 0x08020000
def u32(o): return struct.unpack_from('<I', dec, o)[0]
tb = 0x48A
base = tb + u32(tb); limit = tb + u32(tb + 4)
print(f"region table: file 0x{tb:x}; entries 0x{base:x}..0x{limit:x} ({(limit-base)//16} regions)")
print(f"  (runtime addrs = BASE+file_off for flash; RAM exec shown absolute)")
def kind(a):
    if 0x20000000 <= a < 0x20030000: return "SRAM"
    if 0x10000000 <= a < 0x10010000: return "CCM"
    if 0x08000000 <= a < 0x08100000: return "FLASH"
    return "?"
n = 0
for e in range(base, limit, 16):
    r0, r1, r2, r3 = u32(e), u32(e+4), u32(e+8), u32(e+12)
    fn = ((base - 1) - r3) if (r3 & 1) else r3
    # load/exec may be offset-encoded relative to table base too; show raw + decoded guesses
    print(f"\n region {n}: file 0x{e:06x} (runtime 0x{BASE+e:08x})")
    print(f"   raw r0=0x{r0:08x} r1=0x{r1:08x} r2=0x{r2:08x} r3=0x{r3:08x}")
    print(f"   init_fn=0x{fn:08x} (file 0x{fn-BASE:06x})" if fn >= BASE else f"   init_fn=0x{fn:08x}")
    # interpret r0/r1 as absolute or as offsets from table base
    for nm, v in (("load", r0), ("exec", r1)):
        cands = [v, base + v, (base - 1) - v]
        s = " ".join(f"0x{c:08x}[{kind(c)}]" for c in cands)
        print(f"   {nm}: {s}")
    print(f"   size r2=0x{r2:x} ({r2})")
    n += 1
    if n > 40: print("...truncated"); break
