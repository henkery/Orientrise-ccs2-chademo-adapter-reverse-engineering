#!/usr/bin/env python3
"""Triage a dumped STM32F4 bootloader (acq/dump/boot.bin) — READ-ONLY analysis.

After a non-destructive SWD/UART/DFU dump (acq/swd_dump.sh etc.), this checks the
vector table, disassembles the reset/startup code, and hunts for the update/launch
machinery the REPORT says lives in the bootloader (§5.6 / §8.2b): the XOR key 2B 23,
the $$DATA/$$MAINARM magic, the prefix stream-cipher + 'XIE22.00' footer, FLASH_KEYR
constants, the app-launch jump to 0x08020000, and any USB/DFU/recovery strings.

Structural triage runs with plain python3; disassembly needs capstone:
  nix-shell -p python3 python3Packages.capstone --run 'python3 acq/analyze_boot.py acq/dump/boot.bin'
Usage: python3 analyze_boot.py <boot.bin> [base_hex]   (base default 0x08000000)
"""
import sys, struct, re

BASE = 0x08000000

def u32(d, o):
    return struct.unpack_from('<I', d, o)[0]

def vector_table(d, base):
    if len(d) < 8:
        print("[-] image too small for a vector table"); return None
    sp, rst = u32(d, 0), u32(d, 4)
    print(f"[vector] word0 initial SP = 0x{sp:08x}")
    print(f"[vector] word1 reset vec  = 0x{rst:08x}")
    sp_ok = (0x20000000 <= sp <= 0x20030000) or (0x10000000 <= sp <= 0x10010000)
    rst_ok = (0x08000001 <= rst < 0x08100000) and (rst & 1)
    if sp_ok and rst_ok:
        print("[vector] SANE Cortex-M vector table -> dump looks like RDP Level 0. [C]")
        return rst & ~1
    print("[vector] NOT sane -> RDP1/2 (protected read returns garbage/0), wrong base,")
    print("         or not a bootloader image. Do NOT unlock; re-check probe (README).")
    return None

def disasm_reset(d, base, reset_addr, n=80):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        print("[disasm] capstone not available — skip (run under nix-shell, see header)"); return
    off = reset_addr - base
    if not (0 <= off < len(d)):
        print(f"[disasm] reset addr 0x{reset_addr:08x} outside dump"); return
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    print(f"\n[disasm] reset/startup @ 0x{reset_addr:08x} (f+0x{off:06x}):")
    for i in md.disasm(d[off:off + n * 4], reset_addr):
        print(f"  0x{i.address:08x} f+0x{i.address-base:06x}: {i.mnemonic:8s} {i.op_str}")

def hunt(d, base):
    print("\n[hunt] update / launch machinery (REPORT §5.6 / §8.2b):")
    pats = [(b'\x2b\x23', 'XOR key bytes 2B 23'),
            (b'\x23\x2b', '0x232B (LE halfword)'),
            (b'$$DATA', '$$DATA magic'), (b'$$MAINARM', '$$MAINARM magic'),
            (b'$$BOOT', '$$BOOT magic'), (b'XIE22.00', 'prefix footer XIE22.00'),
            (b'\x23\x01\x67\x45', 'FLASH_KEYR 0x45670123'),
            (b'\xab\x89\xef\xcd', 'FLASH_KEYR 0xCDEF89AB')]
    for pat, label in pats:
        hits = [m.start() for m in re.finditer(re.escape(pat), d)]
        if hits:
            shown = ", ".join(f"f+0x{h:06x}(0x{base+h:08x})" for h in hits[:8])
            more = f" ...(+{len(hits)-8})" if len(hits) > 8 else ""
            print(f"  [+] {label}: {shown}{more}")
    app = [o for o in range(0, len(d) - 3, 4) if 0x08020000 <= u32(d, o) < 0x080C0000]
    if app:
        print(f"  [+] {len(app)} aligned words in app range 0x08020000..0x080C0000 (launch/VTOR candidates):")
        for o in app[:12]:
            print(f"        f+0x{o:06x} (0x{base+o:08x}) = 0x{u32(d,o):08x}")
    for val, name in [(0x40023800, 'RCC'), (0x40023C00, 'FLASH'), (0x50000000, 'USB_OTG_FS'),
                      (0x40006400, 'CAN1'), (0x40006800, 'CAN2'), (0xE000ED0C, 'SCB_AIRCR')]:
        hits = [m.start() for m in re.finditer(re.escape(struct.pack('<I', val)), d)]
        if hits:
            print(f"  [+] {name} 0x{val:08x}: " + ", ".join(f"f+0x{h:06x}" for h in hits[:6]))

def strings(d, base, minlen=6, limit=50):
    seen = set(); out = []
    for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minlen, d):
        s = m.group()
        if s not in seen:
            seen.add(s); out.append((m.start(), s))
    print(f"\n[strings] {len(out)} unique >= {minlen} chars (first {limit}):")
    for o, s in out[:limit]:
        print(f"  f+0x{o:06x} (0x{base+o:08x})  {s.decode('ascii','replace')}")
    kw = re.compile(rb'BOOT|UPG|USB|DFU|UPDATE|UPGRADE|FLASH|RECOVER|XIE|MAINARM|VERSION|JUMP|APP', re.I)
    rel = [(o, s) for o, s in out if kw.search(s)]
    if rel:
        print(f"\n[strings] update/recovery-relevant ({len(rel)}):")
        for o, s in rel[:60]:
            print(f"  f+0x{o:06x}  {s.decode('ascii','replace')}")

def main():
    path = sys.argv[1]
    base = int(sys.argv[2], 16) if len(sys.argv) > 2 else BASE
    d = open(path, 'rb').read()
    print(f"=== {path}: {len(d)} bytes, base 0x{base:08x} ===")
    rst = vector_table(d, base)
    if rst is not None:
        disasm_reset(d, base, rst)
    hunt(d, base)
    strings(d, base)
    print("\n[done] READ-ONLY triage. Feed findings back into REPORT §5.6 / §8.2b.")

if __name__ == '__main__':
    main()
