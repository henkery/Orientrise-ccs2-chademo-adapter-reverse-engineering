#!/usr/bin/env python3
"""Hunt vendor/device-identification strings in the decoded firmware image.

The Orientrise-branded UPG may be a clone; look for the REAL maker's fingerprints:
company names, PLC/SoC silicon vendors, copyright/URLs, model/HW/SW banner templates,
and the log/INFO.TXT format strings seen on the USB stick. Read-only.

Usage: nix-shell -p python3 --run 'python3 analyze38.py firmware.bin'
"""
import sys, re, struct
dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000

KEYWORDS = [
    'orient', 'annapurna', 'qualcomm', 'atheros', 'qca', 'lumissil', 'vertexcom',
    'marvell', 'broadcom', 'realtek', 'mediatek', 'stmicro', 'gigadevice', 'artery',
    'chademo', 'ccs', 'gbt', 'gb/t', 'din70121', 'din 70121', 'iso15118', 'iso 15118',
    'evcc', 'secc', 'copyright', '(c)', 'http', 'www.', '.com', '.cn', '.net', '@',
    'mail', 'model', 'made in', 'shenzhen', 'beijing', 'hangzhou', 'guangdong',
    'technology', 'tech', 'co.,', 'co.', 'ltd', 'inc', 'gmbh', 'version',
    'hw :', 'sw :', 'ser:', 'rtc:', 'evcc1.0', 'upgrade:', 't008', 'main_ccs',
    'boot_ccs', 'serial', 'manufact', 'product', 'vendor', 'brand', 'oem',
    'orientrise', 'rise', 'adapter', 'converter', 'protocol', 'greenphy', 'homeplug',
    'slac', 'sdp', 'v2g', 'plc', 'modem', 'firmware', 'bootloader', 'stm32',
]
kw = [k.lower() for k in KEYWORDS]

print("=== identification-keyword string hits (>=4 printable chars) ===")
seen = set()
hits = []
for m in re.finditer(rb'[\x20-\x7e]{4,}', dec):
    s = m.group().decode('latin1'); low = s.lower()
    if any(k in low for k in kw):
        key = (m.start(), s)
        if key in seen: continue
        seen.add(key)
        hits.append((m.start(), s))
for o, s in hits:
    print(f"  f+0x{o:06x} 0x{BASE+o:08x}: {s}")
print(f"  ({len(hits)} hits)")

print("\n=== banner / format-template context (raw bytes around key anchors) ===")
for anchor in [b'EVCC1.0', b'HW :', b'SW :', b'SER:', b'RTC:', b'UPGRADE:', b'MAC:',
               b'EVCC[', b'MAIN_CCS2CHADEMO', b'BOOT_CCS2CHADEMO', b'.UPG', b'.LST',
               b'INFO.TXT', b'LOGS.BIN']:
    for m in re.finditer(re.escape(anchor), dec):
        o = m.start()
        lo = max(0, o - 16); hi = min(n, o + 64)
        ctx = dec[lo:hi]
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"  {anchor!r} @ f+0x{o:06x}: ...{asc}...")

print("\n=== all distinct strings >=8 chars NOT matching keywords (manual eyeball, first 200) ===")
cnt = 0
seen2 = set()
for m in re.finditer(rb'[\x20-\x7e]{8,}', dec):
    s = m.group().decode('latin1'); low = s.lower()
    if any(k in low for k in kw): continue
    if s in seen2: continue
    seen2.add(s)
    # skip pure hex/pool-looking and repetitive
    if re.fullmatch(r'[0-9a-fA-FxX .]+', s): continue
    print(f"  f+0x{m.start():06x}: {s}")
    cnt += 1
    if cnt >= 200: break