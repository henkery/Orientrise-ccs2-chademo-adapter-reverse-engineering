#!/usr/bin/env python3
"""analyze107c.py — boot recovery-entry trace, pass 3: BL call-graph xrefs.

Scans every BL site in boot sector 0 (f+0x0..0x4000) and reports the callers of the
recovery/launch key functions, to confirm the top-level update-vs-launch structure:
  f+0x6a0 startup, f+0x9ae update wrapper, f+0x8b2 boot-mode decision, f+0xe04 intake,
  f+0x119e boot->app jump, f+0x1190 BOOT/TOOB magic write, f+0x7b0 verifier,
  f+0x1108 xPAI cmd handler, f+0x1926 launch cluster, f+0xc5e XMODEM, f+0x2168 install.
Also lists every BL target that lands in the RAM trampoline range and the reset chain.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze107c.py acq/dump/boot.bin'
"""
import sys, struct, collections
BASE = 0x08000000
d = open(sys.argv[1], 'rb').read(); n = len(d)
def u16(o): return struct.unpack_from('<H', d, o)[0]
def bl_target(a):
    h1 = u16(a); h2 = u16(a + 2)
    if (h1 >> 11) != 0x1E or (h2 & 0xD000) != 0xD000: return None
    S = (h1 >> 10) & 1; imm10 = h1 & 0x3FF; J1 = (h2 >> 13) & 1; J2 = (h2 >> 11) & 1; imm11 = h2 & 0x7FF
    I1 = 1 - ((J1 ^ S) & 1); I2 = 1 - ((J2 ^ S) & 1)
    off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    if off & (1 << 24): off -= 1 << 25
    return (a + 4) + off   # file-relative target

callers = collections.defaultdict(list)
for a in range(0, 0x4000 - 3, 2):
    h1 = u16(a)
    if (h1 >> 11) == 0x1E and (u16(a + 2) & 0xD000) == 0xD000:
        t = bl_target(a)
        if t is not None and 0 <= t < 0x4000:
            callers[t].append(a)

keys = {
    0x6a0: 'startup (calls wrapper)', 0x9ae: 'UPDATE WRAPPER', 0x8b2: 'BOOT-MODE DECISION',
    0xe04: 'INTAKE (XMODEM/USB+install)', 0x119e: 'BOOT->APP JUMP', 0x1190: 'BOOT/TOOB magic write',
    0x7b0: 'app/config verifier', 0x1108: 'xPAI cmd handler', 0x1926: 'launch/update cluster',
    0xc5e: 'XMODEM-1K receiver', 0x2168: 'install dispatcher', 0x11b4: 'FLASH-option (RDP)',
    0x18b6: 'NVIC_SystemReset', 0x430: 'main trampoline (->RAM)', 0x3c: 'reset->main',
    0x103c: 'USB-magic recv', 0x10ce: 'USB recv (ch2)', 0x12e0: 'serial read',
}
print("=== callers of key functions (BL sites in f+0x0..0x4000) ===")
for t, desc in keys.items():
    sites = callers.get(t, [])
    s = ', '.join(f'f+0x{x:06x}' for x in sites) if sites else '(NONE — reached via RAM main / bx / tail-call)'
    print(f"  f+0x{t:06x} {desc:32s}: {s}")

# tail-calls (b.w) to key functions: scan B.W T4 encoding
print("\n=== B.W (tail-call) sites to key functions ===")
def bw_target(a):
    h1 = u16(a); h2 = u16(a + 2)
    if (h1 >> 11) != 0x1E or (h2 & 0xD000) != 0x9000: return None
    S = (h1 >> 10) & 1; imm10 = h1 & 0x3FF; J1 = (h2 >> 13) & 1; J2 = (h2 >> 11) & 1; imm11 = h2 & 0x7FF
    I1 = 1 - ((J1 ^ S) & 1); I2 = 1 - ((J2 ^ S) & 1)
    off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    if off & (1 << 24): off -= 1 << 25
    return (a + 4) + off
for a in range(0, 0x4000 - 3, 2):
    h1 = u16(a)
    if (h1 >> 11) == 0x1E and (u16(a + 2) & 0xD000) == 0x9000:
        t = bw_target(a)
        if t is not None and t in keys:
            print(f"  f+0x{a:06x}: b.w -> f+0x{t:06x} ({keys[t]})")