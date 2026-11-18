#!/usr/bin/env python3
"""Decode Orientrise CCS2->CHAdeMO adapter .UPG firmware update.

Format (reverse engineered):
  - The first 2 raw bytes are a SELF-DESCRIBING key header:
        key[0] = raw[0],  key[1] = raw[0] ^ raw[1]
    and the whole file is XORed with that repeating 2-byte key. The key varies
    per revision (C009 = 2B 23, C013 = 25 A8) and is read from the image, so no
    hardcoded key is needed — the updater/bootloader derives it the same way.
  - Decoded header is ASCII lines "$$<field>\r\n" (DATA, MAINARM, build time,
    version, model, standard tag) after a 2-byte prefix \x00 key[0], then a
    binary/encrypted prefix, then the ARM Cortex-M (STM32F4) application image.

Usage: python3 decode_upg.py <input.UPG> <out.bin> [strings.txt]
"""
import sys, struct

def derive_key(raw: bytes) -> bytes:
    return bytes([raw[0], raw[0] ^ raw[1]])

def decode(data: bytes) -> bytes:
    key = derive_key(data)
    return bytes(b ^ key[i % 2] for i, b in enumerate(data))

def parse_header(dec: bytes):
    # decoded layout: \x00 key[0] then the leading "$$...\r\n" text lines
    hdr = dec[2:0x58]
    fields = [l[2:].decode('ascii', 'replace') for l in hdr.split(b'\r\n')
              if l.startswith(b'$$')]
    return fields

def main():
    src, dst = sys.argv[1], sys.argv[2]
    raw = open(src, 'rb').read()
    dec = decode(raw)
    open(dst, 'wb').write(dec)
    print(f"[+] {src}: {len(raw)} bytes -> {dst} (self-describing XOR key {derive_key(raw).hex(' ')})")
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