#!/usr/bin/env python3
"""Parse the adapter's USB log stick: EVCC_<MAC>_LOGS.BIN (+ INFO.TXT / .LST context).

Empirical record format (from hexdump):
    u32 ts_ms | u16 len | u8 type | u8 crc? | payload[len]
    type 4 = NUL-terminated text log line
    type 1/0 = 60-byte raw Ethernet frame (HomePlug 0x88E1: SLAC / SDP / appHandshake)
Erased tail is 0xFF. Prints every text line, summarizes frames (MMV/MMT, MACs),
and tests the trailing-byte checksum hypothesis. Read-only.

Usage: nix-shell -p python3 --run 'python3 analyze37.py /run/media/iroha/0013-AF1F/EVCC_9CF6DD923FBF_LOGS.BIN'
"""
import sys, struct, collections, re

data = open(sys.argv[1], 'rb').read()
n = len(data)
show_frames = '--frames' in sys.argv

def crc8(buf, poly, init=0):
    c = init
    for b in buf:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c

POLYS = {'sum': None, 'xor': None, 'crc8-07': 0x07, 'crc8-31': 0x31, 'crc8-1D': 0x1D,
         'crc8-9B': 0x9B, 'crc8-D5': 0xD5, 'crc8-39': 0x39, 'crc8-8C': 0x8C,
         'crc8-49': 0x49, 'crc8-E5': 0xE5, 'crc8-A6': 0xA6, 'crc8-2F': 0x2F,
         'crc8-5E': 0x5E, 'crc8-73': 0x73, 'crc8-63': 0x63, 'crc8-B1': 0xB1,
         'crc8-5B': 0x5B, 'crc8-3D': 0x3D, 'crc8-A5': 0xA5, 'crc8-1B': 0x1B,
         'crc8-75': 0x75, 'crc8-65': 0x65, 'crc8-CD': 0xCD, 'crc8-13': 0x13,
         'crc8-E3': 0xE3, 'crc8-79': 0x79, 'crc8-B7': 0xB7, 'crc8-19': 0x19}
match = collections.Counter()
tested = 0

texts = []          # (ts, type, text)
frames = []         # (ts, type, raw)
macs = collections.Counter()
mmts = collections.Counter()
off = 0
bad = 0
segments = 1
while off + 8 <= n:
    if data[off] == 0xFF:                 # erased gap between log segments — skip it
        while off < n and data[off] == 0xFF:
            off += 1
        if off + 8 <= n:
            segments += 1
            print(f"  [segment boundary @ f+0x{off:06x}]")
        continue
    ts, ln, typ, ck = struct.unpack_from('<IHBB', data, off)
    if ln == 0 or ln > 1024 or off + 8 + ln > n:
        bad += 1
        off += 1
        continue
    payload = data[off + 8: off + 8 + ln]
    tested += 1
    for name, poly in POLYS.items():
        if poly is None:
            v = (sum(payload) & 0xFF) if name == 'sum' else 0
            if name == 'xor':
                v = 0
                for b in payload: v ^= b
        else:
            v = crc8(payload, poly)
        if v == ck: match[name] += 1
    if typ == 4 or (payload.endswith(b'\0') and all(32 <= b < 127 or b in (9, 10, 13) for b in payload[:-1])):
        texts.append((ts, typ, payload.rstrip(b'\0').decode('latin1')))
    elif ln == 60 and payload[12:14] == b'\x88\xe1':
        frames.append((ts, typ, payload))
        dst = payload[0:6].hex(':'); src = payload[6:12].hex(':')
        macs[src] += 1; macs[dst] += 1
        mmv = payload[14]; mmt = struct.unpack_from('<H', payload, 15)[0]
        mmts[(mmv, mmt)] += 1
        if show_frames:
            print(f"  [{ts:>9} ms] type{typ} frame dst={dst} src={src} MMV={mmv:#04x} MMT={mmt:#06x}")
            print(f"      {payload[14:].hex(' ')}")
    else:
        texts.append((ts, typ, f"<binary {ln}B> {payload[:32].hex(' ')}"))
    off += 8 + ln

print(f"=== parsed {tested} records, {off} bytes consumed ({off*100//n}%), {bad} resync skips ===")
print(f"=== trailing-byte checksum hypothesis (matches / {tested}) ===")
for name, c in match.most_common(8):
    print(f"  {name:10s}: {c}")
if not match:
    print("  (none of sum/xor/common CRC8 polys match — byte is not a payload checksum)")

print(f"\n=== ALL TEXT RECORDS ({len(texts)}) ===")
for ts, typ, t in texts:
    print(f"  [{ts:>9} ms] t{typ}: {t}")

print(f"\n=== FRAME SUMMARY ({len(frames)} frames) ===")
print("  MACs seen (src+dst):")
for m, c in macs.most_common():
    print(f"    {m}  x{c}")
print("  HomePlug MMV/MMT counts:")
HP = {(0x01, 0x6064): 'CM_SLAC_PARM.REQ', (0x01, 0x6065): 'CM_SLAC_PARM.CNF',
      (0x01, 0x606A): 'CM_START_ATTEN_CHAR.IND', (0x01, 0x606B): 'CM_START_ATTEN_CHAR.RSP',
      (0x01, 0x606C): 'CM_ATTEN_CHAR.IND', (0x01, 0x606D): 'CM_ATTEN_CHAR.RSP',
      (0x01, 0x606E): 'CM_MNBC_SOUND.IND', (0x01, 0x606F): 'CM_ATTEN_PROFILE.IND',
      (0x01, 0x6070): 'CM_VALIDATE.REQ', (0x01, 0x6071): 'CM_VALIDATE.CNF',
      (0x01, 0x6072): 'CM_SLAC_MATCH.REQ', (0x01, 0x6073): 'CM_SLAC_MATCH.CNF',
      (0x01, 0x6074): 'CM_SLAC_CHANGE_ATTEN.IND', (0x01, 0x6075): 'CM_SLAC_CHANGE_ATTEN.RSP',
      (0x00, 0xA062): '?MMV0 A062', (0x00, 0xA063): '?MMV0 A063'}
for (mmv, mmt), c in sorted(mmts.items()):
    print(f"    MMV={mmv:#04x} MMT={mmt:#06x}  x{c}  {HP.get((mmv, mmt), '')}")

print("\n=== identification-relevant strings (whole file, >=6 printable) ===")
seen = set()
for m in re.finditer(rb'[\x20-\x7e]{6,}', data):
    s = m.group().decode()
    if s not in seen:
        seen.add(s)
        print(f"  f+0x{m.start():06x}: {s}")