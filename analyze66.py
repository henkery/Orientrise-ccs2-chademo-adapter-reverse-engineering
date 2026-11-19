#!/usr/bin/env python3
"""Independent verification of the built service UPGs + FatFs finalizer identification.
 (1) SERVICE.UPG must be byte-identical to the stock raw UPG (round-trip proof).
 (2) SERVICE_DUMP.UPG: re-derive key, re-decode, independently recompute MODBUS footer
     + trailer CRCs, check length field, disasm the in-place hook site (f_close 0x0368E8
     -> b.w cave) + its resume point (f_close+4 0x0368EC) and the cave (0x92000), confirm
     cave within sector 9, confirm entry/first4 preserved.
 (3) disasm f_sync 0x03685A + f_close 0x0368E8 from stock (f_close calls f_sync to flush
     the dir-entry size, then validates+clears fp->obj.fs — the dump cave's finalizer).
Usage: nix-shell -p python3 python3Packages.capstone --run 'python3 analyze66.py SERVICE.UPG SERVICE_DUMP.UPG ../extracted/MAIN_CCS2CHADEMO_1.UPG firmware.bin'
"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
BASE = 0x08020000
TAB = []
for i in range(256):
    c = i
    for _ in range(8): c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    TAB.append(c)
def modbus(d):
    c = 0xFFFF
    for b in d: c = (c >> 8) ^ TAB[(c ^ b) & 0xFF]
    return c
def key_of(raw): return bytes([raw[0], raw[0] ^ raw[1]])
def dec_of(raw):
    k = key_of(raw); return bytes(b ^ k[i & 1] for i, b in enumerate(raw))
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
def disasm(dec, start, end, label):
    print(f"\n--- {label} ---")
    for i in md.disasm(dec[start:end], BASE + start):
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}")

svc = open(sys.argv[1], 'rb').read(); dump = open(sys.argv[2], 'rb').read()
stock = open(sys.argv[3], 'rb').read(); sdec = open(sys.argv[4], 'rb').read()
print(f"(1) SERVICE.UPG byte-identical to stock: {svc == stock}  ({len(svc)} vs {len(stock)} B)")

d = dec_of(dump); n = len(d)
print(f"\n(2) SERVICE_DUMP.UPG decoded={n} (0x{n:x}) key={key_of(dump).hex()}")
foot = struct.unpack_from('<H', d, 0x3FE)[0]; tr = struct.unpack_from('<H', d, n - 2)[0]
print(f"  footer stored=0x{foot:04X} calc=0x{modbus(d[0x3EA:0x3FE]):04X} {'OK' if foot==modbus(d[0x3EA:0x3FE]) else 'BAD'}")
print(f"  trailer stored=0x{tr:04X} calc=0x{modbus(d[2:n-2]):04X} {'OK' if tr==modbus(d[2:n-2]) else 'BAD'}")
ln = struct.unpack_from('<I', d, 0x3F2)[0]
print(f"  length field=0x{ln:x} expect n-0x404=0x{n-0x404:x} {'OK' if ln==n-0x404 else 'BAD'}")
print(f"  trailer key-echo d[n-4:n-2]={d[n-4:n-2].hex()} (expect 0000)")
print(f"  first4@400=0x{struct.unpack_from('<I',d,0x400)[0]:08X} stock=0x{struct.unpack_from('<I',sdec,0x400)[0]:08X} {'OK' if d[0x400:0x404]==sdec[0x400:0x404] else 'BAD'}")
print(f"  entry[400:45E] preserved: {d[0x400:0x45E]==sdec[0x400:0x45E]}")
print(f"  prefix[0:3EA] preserved: {d[0:0x3EA]==sdec[0:0x3EA]}")
print(f"  cave end f+0x{n-4:06x} < sector9 end 0xA0000: {n-4 < 0xA0000}")
disasm(d, 0x0368E8, 0x0368F4, "hook site f_close 0x0368E8 (expect b.w 0x080b2000, then resume bl f_sync)")
disasm(d, 0x92000, n - 4, "cave 0x92000 (dump sequence + fin epilogue + path)")

fdec = sdec
disasm(fdec, 0x03685A, 0x0368E8, "f_sync 0x03685A (dir-entry size flush)")
disasm(fdec, 0x0368E8, 0x036940, "f_close 0x0368E8 (calls f_sync, validates, clears obj.fs)")
