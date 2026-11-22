#!/usr/bin/env python3
"""analyze108.py — USB-device feasibility + SPI-flash write protocol for the CDC revert aid.

Two prerequisites for a TinyUSB device-CDC revert-from-custom channel:
  (1) Does the boot use USB OTG_FS in DEVICE mode (proves the connector supports device CDC),
      or only HOST? Scan boot strings + 0x50000000/0x40040000 LDR-literal xrefs + USB init.
  (2) The SPI-flash WRITE/ERASE protocol behind the xPAI staging path: boot SPI read f+0x1ace
      (64B @off0) + write f+0x1b42 (4B @off0) + the low-level SPI flash command driver, so the
      custom app can stage SERVICE.UPG @SPI 0x100000 + write the xPAI descriptor @SPI 0.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze108.py acq/dump/boot.bin > .qwen/tmp/ccs2_re/a108.out'
"""
import sys, struct, re, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
BASE = 0x08000000
d = open(sys.argv[1], 'rb').read(); n = len(d)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', d, o)[0]
def u32(o): return struct.unpack_from('<I', d, o)[0]
def bl_target(a):
    h1 = u16(a); h2 = u16(a + 2)
    if (h1 >> 11) != 0x1E or (h2 & 0xD000) != 0xD000: return None
    S = (h1 >> 10) & 1; imm10 = h1 & 0x3FF; J1 = (h2 >> 13) & 1; J2 = (h2 >> 11) & 1; imm11 = h2 & 0x7FF
    I1 = 1 - ((J1 ^ S) & 1); I2 = 1 - ((J2 ^ S) & 1)
    off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    if off & (1 << 24): off -= 1 << 25
    return BASE + (a + 4) + off
SYSREG = {0x08: 'MSP', 0x09: 'PSP', 0x10: 'PRIMASK', 0x11: 'BASEPRI', 0x13: 'FAULTMASK', 0x14: 'CONTROL'}

print("===== boot ASCII strings (USB / serial / update keywords) =====")
kw = re.compile(rb'(USB|usb|CDC|MSC|HID|DFU|device|Device|DEVICE|host|Host|HOST|OTG|otg|serial|Serial|XMODEM|xmodem|UPG|upgrade|Upgrade|UPGRADE|enumerat|Enumerat|VID|PID|VBUS|vbus|mass|Mass|storage|Storage|CDC ACM|tty|COM)')
for m in re.finditer(rb'[\x20-\x7e]{5,}', d):
    s = m.group()
    if kw.search(s):
        print(f"  f+0x{m.start():06x}: {s.decode('ascii', 'replace')}")

print("\n===== USB OTG_FS/HS (0x50000000/0x40040000) + SPI4 (0x40013400) LDR-literal xrefs =====")
targets = {0x50000000: 'USB_OTG_FS', 0x40040000: 'USB_OTG_HS', 0x40013400: 'SPI4',
           0x40023C00: 'FLASH', 0x40003000: 'IWDG'}
hits = collections.defaultdict(list)
a = 0
while a < 0x4000:
    h1 = u16(a); t = None
    if (h1 & 0xFF7F) == 0xF85F and a + 4 <= 0x4000:
        h2 = u16(a + 2); u = (h1 >> 7) & 1
        t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
    elif (h1 & 0xF800) == 0x4800:
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
    if t is not None and 0 <= t < n - 3:
        w = u32(t)
        if w in targets: hits[w].append(a)
    a += 2
for w, desc in targets.items():
    sites = hits.get(w, [])
    print(f"  0x{w:08X} {desc:12s}: " + (', '.join(f'f+0x{x:06x}' for x in sites) if sites else '(none)'))

def disasm_range(lo, hi, label):
    print(f"\n===== {label}  f+0x{lo:06x}..0x{hi:06x} =====")
    regimm = {}; a = lo
    while a < hi:
        ins = list(md.disasm(d[a:a + 8], BASE + a, count=1)); h1 = u16(a)
        if not ins and (h1 & 0xFFF0) == 0xF380 and a + 2 < hi and (u16(a + 2) & 0xFF00) == 0x8800:
            sysm = u16(a + 2) & 0xFF; rn = h1 & 0xF
            print(f"  f+0x{a:06x}: msr {SYSREG.get(sysm, hex(sysm))}, r{rn} (manual)"); a += 4; continue
        if not ins:
            print(f"  f+0x{a:06x}: .hword 0x{u16(a):04x}"); a += 2; continue
        ins = ins[0]; note = ''; mn = ins.mnemonic; ops = ins.op_str
        if mn == 'bl':
            t = bl_target(a)
            if t is not None: note = f"   -> f+0x{t-BASE:06x}"
        elif (h1 & 0xFF7F) == 0xF85F and ins.size == 4:
            h2 = u16(a + 2); u = (h1 >> 7) & 1
            t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
            if 0 <= t < n - 3: note = f"   [pool=0x{u32(t):08X}]"
        elif (h1 & 0xF800) == 0x4800:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            if t < n - 3: note = f"   [pool=0x{u32(t):08X}]"
        elif (h1 & 0xF800) == 0xA000:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            s = d[t:t + 40].split(b'\x00')[0]
            pr = s.decode('ascii', 'replace') if len(s) >= 2 and all(32 <= c < 127 for c in s) else ''
            note = f"   [adr {pr!r}]"
        elif mn in ('movw', 'movt') and len(ins.operands) == 2:
            rn = ins.reg_name(ins.operands[0].reg) or ''; imm = ins.operands[1].imm
            if rn.startswith('r') and rn[1:].isdigit():
                rd = int(rn[1:])
                if mn == 'movw': regimm[rd] = imm
                else: note = f"   ; r{rd}=0x{(imm<<16)|regimm.get(rd,0):08X}"
        print(f"  f+0x{a:06x}: {mn:9s} {ops}{note}")
        a += ins.size

disasm_range(0x1ace, 0x1d68, "SPI read f+0x1ace + write f+0x1b42 + helpers")