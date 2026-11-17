#!/usr/bin/env python3
"""Decode Orientrise CCS2->CHAdeMO adapter .UPG firmware update.

Format (reverse engineered):
  - Whole file XORed with repeating 2-byte key [0x2B, 0x23].
  - Decoded header is ASCII lines "$$<field>\r\n" (DATA, MAINARM, build time,
    version, model, standard tag), then a binary/encrypted prefix, then the
    ARM Cortex-M (STM32F4) application image.

Usage: python3 decode_upg.py <input.UPG> <out.bin> [strings.txt]
"""
import sys, struct

KEY = bytes([0x2B, 0x23])

def decode(data: bytes) -> bytes:
    return bytes(b ^ KEY[i % 2] for i, b in enumerate(data))

def parse_header(dec: bytes):
    # header is the leading run of "$$...\r\n" text lines (after a 2-byte prefix)
    end = dec.find(b'\x00', 2)
    # header text ends where non-text binary begins; scan for last \r\n of $$ block
    hdr = dec[:0x58]
    fields = [l[2:].decode('ascii', 'replace') for l in hdr.split(b'\r\n')
              if l.startswith(b'$$')]
    return fields

def main():
    src, dst = sys.argv[1], sys.argv[2]
    raw = open(src, 'rb').read()
    dec = decode(raw)
    open(dst, 'wb').write(dec)
    print(f"[+] {src}: {len(raw)} bytes -> {dst} (XOR key {KEY.hex(' ')})")
    print("[+] header fields:")
    for f in parse_header(dec):
        print(f"      {f}")
    if len(sys.argv) > 3:
        import re
        seen = set(); out = []
        for m in re.finditer(rb'[\x20-\x7e]{6,}', dec):
            s = m.group()
            if s not in seen:
                seen.add(s); out.append((m.start(), s))
        with open(sys.argv[3], 'w') as fh:
            for off, s in out:
                fh.write(f"0x{off:06x}  {s.decode('ascii','replace')}\n")
        print(f"[+] {len(out)} unique strings >=6 chars -> {sys.argv[3]}")

if __name__ == '__main__':
    main()