#!/usr/bin/env python3
"""analyze70.py — running-app sector-5 dump analysis (acq/dump/app5.bin).

Resolves the paused "prefix-decrypt" hunt with GROUND TRUTH. SERVICE_DUMP_APP5.UPG
(REPORT §5.13i) dumped the running app's sector 5 (0x08020000..0x08040000) to APP5.BIN.
Comparing that plaintext against the stored decoded image (firmware.bin) proves:

  * APP5[x] == firmware.bin[x + 0x402] for the whole 128 KB (100%, pure shift, NO
    halfword swap, NO cipher). The boot strips a 0x402-byte header and installs
    fw[0x402:] VERBATIM to 0x08020000.
  * The "encrypted prefix" fw[0x58:0x3EA] (914 B, entropy ~7.8) lies INSIDE the stripped
    header => DISCARDED, never installed, never decrypted. There is no prefix cipher
    (which is why the exhaustive boot trace, §5.15, found no decrypt routine).
  * True link base = 0x0801FBFE (fw[F] -> 0x0801FBFE+F). App reset handler fw[0x40A] ->
    0x08020008; app main entry 0x08020054. Standard ARM C-library startup, NO boot-patched
    literals (the earlier "0x44C/0x450 placeholders" were a wrong-base artifact).
  * The §5.13b "+2-packed literal pools" pack is REAL but LOCAL to the SRAM-copied flash
    writer (fixed up at copy time, still encoded in flash); in-place code is plaintext.

Usage:
  nix-shell -p python3 python3Packages.capstone --run \
    'python3 analyze70.py acq/dump/app5.bin firmware.bin'
"""
import sys, struct, math
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

BASE = 0x08020000            # APP5 runtime base (sector 5)
STRIP = 0x402               # header bytes the boot strips before install
TRUE_BASE = BASE - STRIP    # 0x0801FBFE: firmware.bin[F] -> TRUE_BASE+F

def u32(b, o): return struct.unpack_from('<I', b, o)[0]
def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def entropy(d):
    if not d: return 0.0
    c = [0]*256
    for x in d: c[x] += 1
    return -sum((n/len(d))*math.log2(n/len(d)) for n in c if n)

def main():
    app_path = sys.argv[1] if len(sys.argv) > 1 else 'acq/dump/app5.bin'
    fw_path  = sys.argv[2] if len(sys.argv) > 2 else 'firmware.bin'
    app = open(app_path, 'rb').read()
    fw  = open(fw_path, 'rb').read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
    N = len(app)
    print(f"APP5 = {N} (0x{N:x}) B @0x{BASE:08X}; firmware.bin = {len(fw)} (0x{len(fw):x}) B")

    print("\n== 1. install transform: APP5[x] vs fw[x+delta] (match rate) ==")
    best = None
    for delta in (STRIP, 0x400, 0x40A, 0x3EA, 0x58, 0x2, 0x0):
        m = sum(1 for x in range(N) if x+delta < len(fw) and app[x] == fw[x+delta])
        print(f"  delta=0x{delta:04x}: {m}/{N} = {100*m/N:.2f}%")
        if best is None or m > best[1]: best = (delta, m)
    delta, m = best
    print(f"  => BEST delta=0x{delta:x} ({100*m/N:.2f}%). "
          + ("VERBATIM install of fw[0x402:] — no cipher, no swap." if m == N and delta == STRIP
             else "NOT a clean verbatim shift — investigate."))
    # mismatch runs at the best delta (boot patches, if any)
    runs = []; i = 0
    while i < N:
        if i+delta < len(fw) and app[i] != fw[i+delta]:
            j = i
            while j < N and j+delta < len(fw) and app[j] != fw[j+delta]: j += 1
            runs.append((i, j)); i = j
        else: i += 1
    print(f"  mismatch runs at delta=0x{delta:x}: {len(runs)} (boot-time patches)")
    for a, b in runs[:20]:
        print(f"    APP5[0x{a:05x}:0x{b:05x}] app={app[a:a+8].hex()} fw={fw[a+delta:a+delta+8].hex()}")

    print("\n== 2. vector table (APP5[0:8]) + discarded-prefix proof ==")
    sp, reset = u32(app, 0), u32(app, 4)
    print(f"  initial SP = 0x{sp:08X}  {'VALID SRAM' if 0x20000000 <= sp <= 0x20030000 else 'INVALID'}")
    print(f"  reset vec  = 0x{reset:08X}  {'VALID thumb' if (reset&1) and 0x08000000 <= (reset&~1) < 0x08100000 else 'INVALID'}"
          f"  -> handler 0x{reset&~1:08X}")
    print(f"  fw[0x402:0x40A] = {fw[0x402:0x40A].hex()} == APP5[0:8] {app[0:8].hex()} : {fw[0x402:0x40A]==app[0:8]}")
    print(f"  'encrypted prefix' fw[0x58:0x3EA]: {0x3EA-0x58} B, entropy {entropy(fw[0x58:0x3EA]):.3f} bits/B")
    print(f"  prefix end 0x3EA < strip 0x402 => prefix is INSIDE stripped header => DISCARDED (never installed/decrypted)")
    print(f"  APP5[0x58:0x3EA] entropy {entropy(app[0x58:0x3EA]):.3f} bits/B (= decoded app code, not the prefix)")

    print("\n== 3. app reset handler @0x%08X (APP5+0x8 == fw+0x40A), in-place pools ==" % (BASE+8))
    a = 0x8
    while a < 0x54:
        h1 = u16(app, a)
        ins = list(md.disasm(app[a:a+8], BASE+a, count=1))
        if not ins and (h1 & 0xFFF0) == 0xF380 and (u16(app, a+2) & 0xFF00) == 0x8800:
            sysm = u16(app, a+2) & 0xFF
            nm = {8:'MSP',9:'PSP',0x10:'PRIMASK',0x14:'CONTROL'}.get(sysm, f'SYSm{sysm:02x}')
            print(f"  0x{BASE+a:08x}: msr {nm}, r{h1&0xF}"); a += 4; continue
        if not ins:
            print(f"  0x{BASE+a:08x}: .word 0x{u32(app,a):08X} (pool)"); a += 2; continue
        i = ins[0]; note = ""
        if (h1 & 0xF800) == 0x4800:
            t = ((a+4)&~3)+(h1&0xFF)*4; note = f"   [pool APP5+0x{t:03x}=0x{u32(app,t):08X}]"
        elif (h1 & 0xFF7F) == 0xF85F and i.size == 4:
            h2 = u16(app, a+2); u = (h1>>7)&1
            t = ((a+4)&~3)+((h2&0xFFF) if u else -(h2&0xFFF)); note = f"   [pool APP5+0x{t:03x}=0x{u32(app,t):08X}]"
        print(f"  0x{BASE+a:08x}: {i.mnemonic:9s} {i.op_str}{note}")
        a += i.size
    print(f"  app main entry: bx [APP5+0x50]=0x{u32(app,0x50):08X} -> 0x{u32(app,0x50)&~1:08X}")

    print("\n== 4. true link base verification (internal string pointers) ==")
    print(f"  true base = 0x{TRUE_BASE:08X} (fw[F] -> 0x{TRUE_BASE:08X}+F)")
    hits = 0; ex = []
    for o in range(0x10000, N-4, 4):
        p = u32(app, o)
        if BASE <= p < BASE+N:
            fo = p - BASE
            s = app[fo:fo+24].split(b'\x00')[0]
            if len(s) >= 4 and all(32 <= c < 127 for c in s):
                hits += 1
                if len(ex) < 4: ex.append((o, p, fo, s.decode()))
    print(f"  APP5 pointers landing on ASCII strings: {hits}")
    for o, p, fo, s in ex:
        print(f"    ptr@APP5+0x{o:05x}=0x{p:08X} -> APP5+0x{fo:05x} (fw+0x{fo+STRIP:05x}) {s!r}")

    print("\n== CONCLUSION ==")
    print("  Boot install = XOR-decode (2-byte key) + strip 0x402-byte header + VERBATIM copy fw[0x402:]")
    print("  to 0x08020000. No prefix-decrypt; the high-entropy prefix is a discarded header field.")
    print("  App is a standard ARM C image: reset@0x08020008 self-bootstraps (SP from vector[0], zero")
    print("  SRAM+CCM, scatterload, __main). Protection = 2-byte XOR only (REPORT §6 confirmed).")

if __name__ == '__main__':
    main()