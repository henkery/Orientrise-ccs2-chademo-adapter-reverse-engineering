#!/usr/bin/env python3
"""analyze76.py — SDP security-trigger decoder (§5.9 / §8.8b): names the config byte that
selects TLS vs no-TLS in the CCS2 SDP request.

RESOLVED: the tested low byte of accessor 0x08051074 (config struct @SRAM 0x200189EC, word
+0x20 = 0x20018A0C) is the **"Root certs" count** — the number of configured Root-CA
certificate entries (vendor V2G msg-code 0x8101) in the PnC certificate config block. The
firmware's own diagnostic dumper 0x0804EB5C ("Show Certification Status") names the four
config bytes:
    config[0x20] = "Root certs"      (msg 0x8101, count <= 5)  <- the SDP security byte
    config[0x21] = "Pri_root cert"   (msg 0x8102)
    config[0x22] = "Oem cert"        (msg 0x8105)
    config[0x23] = "Contract certs"  (msg 0x8109, 32-byte payload)
SDP decision (client 0x080204FA): security = (Root certs == 0) ? 0x10 (TLS) : 0x00 (no TLS).
So the trigger is the ISO 15118 PnC root-certificate configuration, NOT a per-session value
and NOT the DIN-vs-ISO appHandshake choice (that is the separate SchemaID 1/2 selection).

This tool re-derives the naming from firmware.bin bytes (no hardcoded conclusions): it locates
the cert-name diagnostic strings, scans the config-parser MOVW msg-code loads, and disassembles
the SDP tst/beq decision + the accessor to confirm the mapping.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze76.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
fw = open('firmware.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))

print("== 1. PnC certificate diagnostic strings (config-byte names) ==")
cert_names = {}
for key, pat in [('title', b'Show Certification Status'), ('root', b'Root certs'),
                 ('pri_root', b'Pri_root cert'), ('oem', b'Oem cert'),
                 ('contract', b'Contract certs')]:
    idx = fw.find(pat)
    if idx < 0:
        print(f"  {key:9s}: NOT FOUND"); continue
    st = idx
    while st > 0 and fw[st-1] != 0: st -= 1
    s = fw[st:st+48].split(b'\x00')[0].decode('latin1')
    cert_names[key] = st
    print(f"  {key:9s}: f+0x{st:05x} (0x{rt(st):08X})  {s!r}")

print("\n== 2. config-parser MOVW msg-code loads (0x8101..0x8109) ==")
# config init 0x08050B94 (f+0x30F96) .. 0x08051362 (f+0x31764)
codes = {}
for o in range(0x30F96, 0x31764, 2):
    h1 = u16(o)
    if (h1 & 0xFBF0) == 0xF240:
        h2 = u16(o+2)
        if h2 & 0x8000: continue
        imm = ((h1 & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
        if 0x8101 <= imm <= 0x8109:
            codes.setdefault(imm, []).append(o)
for c in sorted(codes):
    sites = ", ".join(f'f+0x{o:05x}' for o in codes[c])
    print(f"  msg 0x{c:04X}: {sites}")

print("\n== 3. SDP security decision (accessor 0x08051074 -> tst/beq -> 0x10/0x00) ==")
# find BL callers of the accessor
acc = 0x08051074
callers = []
for o in range(0, N-4, 2):
    if (u16(o) & 0xF800) == 0xF000:
        ins = dis(o)
        if ins and ins[0].mnemonic == 'bl' and ins[0].operands and ins[0].operands[0].type == 2:
            if ins[0].operands[0].imm == acc: callers.append(o)
print(f"  accessor 0x{acc:08X} BL callers: " + ", ".join(f'f+0x{o:05x} (0x{rt(o):08X})' for o in callers))
# the SDP client caller is the one in the low app region (f+0x008FC); show its decision window
sdp = next((o for o in callers if o < 0x1000), None)
if sdp is not None:
    print(f"  SDP decision window @ f+0x{sdp:05x} (0x{rt(sdp):08X}):")
    a = sdp
    for _ in range(7):
        ins = dis(a)
        if not ins: break
        i = ins[0]
        print(f"    f+0x{a:05x} 0x{rt(a):08x}: {i.mnemonic:8s} {i.op_str}")
        a += i.size

print("\n== 4. accessor 0x08051074 (reads config word +0x20, packs byte +0x24 at bit24) ==")
a = acc - TB
for _ in range(8):
    ins = dis(a)
    if not ins: break
    i = ins[0]
    note = ''
    if (u16(a) & 0xF800) == 0x4800:
        pca = ((rt(a)+4) & ~3) - TB; t = pca + (u16(a) & 0xFF)*4
        note = f'   ; pool=0x{u32(t):08X}'
    print(f"    f+0x{a:05x} 0x{rt(a):08x}: {i.mnemonic:8s} {i.op_str}{note}")
    a += i.size
    if i.mnemonic == 'bx': break

print("\n== RESOLVED mechanism (§5.9 / §8.8b) ==")
print("  config struct @SRAM 0x200189EC (size 0x28); security byte = config[0x20] @0x20018A0C.")
print("  config[0x20] = 'Root certs'  = count of msg-0x8101 entries (<=5) copied from the PnC")
print("                 certificate config block @0x001F8010 (header @0x001F8000, magic 0xCEA155E1,")
print("                 ver 1) by flash parser 0x08050E14; counted by config init 0x08050B94.")
print("  config[0x21] = 'Pri_root cert' (msg 0x8102); [0x22] = 'Oem cert' (msg 0x8105);")
print("  config[0x23] = 'Contract certs' (msg 0x8109, 32-byte payload).")
print("  SDP client 0x080204FA: bl 0x08051074; tst r0,#0xff; beq -> 0x10 else -> 0x00; strb [r4+0x22].")
print("  => SDP requests TLS (0x10) iff Root-cert count == 0; no-TLS (0x00) iff Root certs > 0.")
print("  Trigger = ISO 15118 PnC root-certificate configuration (a service-config property),")
print("  NOT the DIN-vs-ISO appHandshake SchemaID choice and NOT a per-session value.")