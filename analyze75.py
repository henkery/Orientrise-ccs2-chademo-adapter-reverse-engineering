#!/usr/bin/env python3
"""analyze75.py — QCA7005 MAC-read MME decoder (REPORT §5.9 / §8.8a).

Nails the exact MME MMTYPE the STM32 host uses to read the QCA7005 PLC-modem PIB MAC
(the 6-byte EVCCID). The request is built byte-by-byte in code (NOT a static rodata
frame), which is why a naive EtherType/MMTYPE template scan misses it:

  builder   0x08088B48 (f+0x68F4A): copies a 12-byte MAC header from rodata template
            0x080AEC84 (f+0x8F086), then writes EtherType via `movw #0xE188` + `strh`
            (network order ⇒ on-wire 88 E1 = 0x88E1), MMV=0, MMTYPE low/high = 00/A0
            ⇒ MMTYPE 0xA000, payload param=0xB000 + op='R'(0x52) + 4 zero bytes;
            memset reply buffer 0x200227E0; tail-call mme-send 0x080888CE, len 0x18 (24).
  validator 0x08088ADA (f+0x68EDC): accepts the reply only if EtherType 0x88E1, header
            matches template, MMTYPE low==1 / high==0xA0 ⇒ MMTYPE 0xA001 (CNF), stamps
            done-marker 0x55 at payload+3 and copies the reply to SRAM 0x200227E0.
  poll loop 0x08088B1E (f+0x68F20): sends via frame-send 0x08088976 (callback 0x08088ADB),
            waits for the 0x55 marker, 10 ms delay × 20 tries.
  retry     0x08088C74 (f+0x69076): build(0x08088B48)+poll(0x08088B1E) up to 3×.
  MAC store SRAM 0x200227E6 (= reply buffer 0x200227E0 + 6); accessor 0x08088CAC returns
            it — the same bytes used as SLAC EVHost-MAC and ISO SessionSetupReq EVCCID.

The template dest MAC 00:B0:52:00:00:01 is the QCA7005 *default* PIB MAC (the host does
not yet know the real one); the 0xA000 read returns the actual per-unit MAC. MMTYPE 0xA000
/0xA001 is a vendor-specific (0xA0xx, MMV=0) PIB/module READ — distinct from the SLAC
CM_* MMEs (0x60xx) which run *after* the MAC is known.

Usage:
  nix-shell -p python3 --run 'python3 analyze75.py'
"""
import struct
fw = open('firmware.bin', 'rb').read()
TB = 0x0801FBFE
TEMPLATE_F = 0x080AEC84 - TB          # f+0x8F086, 12-byte MAC header template
tpl = fw[TEMPLATE_F:TEMPLATE_F + 12]

# Reconstruct the 24-byte MAC-read request frame exactly as builder 0x08088B48 writes it.
frame = bytearray(24)
frame[0x00:0x0C] = tpl                # dest MAC (6) + src MAC (6) from template
frame[0x0C:0x0E] = b'\x88\xe1'        # EtherType 0x88E1 (movw #0xE188, strh network-order)
frame[0x0E] = 0x00                    # MMV = 0
frame[0x0F] = 0x00                    # MMTYPE low  = 0x00
frame[0x10] = 0xA0                    # MMTYPE high = 0xA0  ⇒ MMTYPE 0xA000 (REQ)
frame[0x11] = 0x00                    # payload param low  = 0x00
frame[0x12] = 0xB0                    # payload param high = 0xB0 ⇒ param 0xB000
frame[0x13] = 0x52                    # payload op = 'R' (0x52, Read)
frame[0x14:0x18] = b'\x00\x00\x00\x00'  # payload[3..6] = 0 (reply[3] becomes 0x55 done-marker)

print("== QCA7005 MAC-read request MME (builder 0x08088B48, len 0x18=24) ==")
print(f"  header template @0x080AEC84 (f+0x{TEMPLATE_F:05x}): {tpl.hex(' ')}")
print(f"  dest MAC = {tpl[0:6].hex(':')}  (QCA7005 default PIB MAC)")
print(f"  src  MAC = {tpl[6:12].hex(':')}  (host)")
print("  reconstructed frame:")
fields = [(0x00, 6, 'dest MAC'), (0x06, 6, 'src MAC'), (0x0C, 2, 'EtherType 0x88E1'),
          (0x0E, 1, 'MMV=0'), (0x0F, 2, 'MMTYPE 0xA000 (REQ)'), (0x11, 2, 'param 0xB000'),
          (0x13, 1, "op 'R'=0x52 (Read)"), (0x14, 4, 'reserved 0 / reply done-marker')]
for off, n, name in fields:
    print(f"    +0x{off:02x}  {frame[off:off+n].hex(' '):14s}  {name}")
print(f"  raw: {frame.hex(' ')}")

print("\n== MMTYPE map (decoded from SLAC/PLC code, REPORT §5.9) ==")
mmtypes = [
    (0xA000, 0xA001, 'VS PIB/module READ — MAC read (param 0xB000, op R)', '0x08088B48 / 0x08088ADA'),
    (0xA062, None,   'VS PIB read (param 0xB000, op R) — SLAC-layer param', '0x080214D6'),
    (0xA0B9, None,   'VS PIB read (param 0xB000, op R) — SLAC-layer param', '0x080214D6'),
    (0x6064, 0x6065, 'CM_SLAC_PARM.REQ / .CNF (EVHost MAC)', '0x0802166E / 0x0802188C'),
    (0x606A, None,   'CM_START_ATTEN_CHAR.IND', '0x0802188C'),
    (0x6008, 0x6009, 'CM_SET_KEY.REQ / .CNF', '0x080214D6'),
]
for req, cnf, name, site in mmtypes:
    pair = f"0x{req:04X}" + (f"/0x{cnf:04X}" if cnf else "")
    print(f"  {pair:13s} {name:52s} {site}")

print("\n== MAC-read call chain ==")
print("  0x08088C74 (retry×3) → 0x08088B48 (build REQ 0xA000) → 0x080888CE (mme-send, len 24)")
print("                       → 0x08088B1E (poll) → 0x08088976 (frame-send) → QCA7005 SPI")
print("  reply CNF 0xA001 → 0x08088ADA (validate, stamp 0x55) → copy to SRAM 0x200227E0")
print("  6-byte MAC @ 0x200227E6 (=+6); accessor 0x08088CAC ⇒ SLAC EVHost-MAC + EVCCID")