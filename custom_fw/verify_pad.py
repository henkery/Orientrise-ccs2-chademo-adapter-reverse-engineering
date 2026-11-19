#!/usr/bin/env python3
"""verify_pad.py — sanity-check the custom app's vector table, then pad to sector-5 size.

The stock bootloader reads vector[1] (reset) @0x08020004 and branches to it; vector[0] is
the initial MSP the app's Reset_Handler loads (REPORT §5.15/§5.16). Checks:
  vector[0] == 0x20030000 (top of 192 KB SRAM, linker.ld _estack)
  vector[1] is a Thumb address (bit0=1) inside the app flash region 0x08020000..0x080BFFFF
Then pads app.bin to 0x20000 (128 KB = sector 5, matching the ground-truth app5.bin dump)
with 0xFF (erased flash) -> app_padded.bin, so the boot's erase/program covers exactly one
sector like a normal app image. Pure stdlib; no hardware touched.
"""
import struct, sys

APP_BASE, APP_END = 0x08020000, 0x080C0000
ESTACK, SECTOR5 = 0x20030000, 0x20000

bin_ = open('app.bin', 'rb').read()
if len(bin_) < 8:
    sys.exit(f"app.bin too small ({len(bin_)} B) — no vector table")
sp, reset = struct.unpack_from('<II', bin_, 0)
print(f"  app.bin = {len(bin_)} B (0x{len(bin_):x})")
print(f"  vector[0] MSP   = 0x{sp:08X}  (expect 0x{ESTACK:08X})")
print(f"  vector[1] reset = 0x{reset:08X}  (handler 0x{reset & ~1:08X}, Thumb bit={reset & 1})")
ok = True
if sp != ESTACK:
    print("  ERROR: MSP != _estack"); ok = False
if not (reset & 1):
    print("  ERROR: reset vector missing Thumb bit"); ok = False
if not (APP_BASE <= (reset & ~1) < APP_END):
    print("  ERROR: reset handler outside app flash region"); ok = False
if len(bin_) > SECTOR5:
    print(f"  ERROR: app.bin exceeds sector 5 ({SECTOR5} B)"); ok = False
if not ok:
    sys.exit(1)
print("  vectors OK: boot will branch to a valid in-app Thumb Reset_Handler.")

padded = bin_ + b'\xFF' * (SECTOR5 - len(bin_))
open('app_padded.bin', 'wb').write(padded)
print(f"  wrote app_padded.bin = {len(padded)} B (0x{len(padded):x}, sector-5 sized, 0xFF tail)")