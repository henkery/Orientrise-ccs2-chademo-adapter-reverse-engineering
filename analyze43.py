#!/usr/bin/env python3
"""CAN timeline for one EXI session in EVCC_<MAC>_LOGS.BIN (t6 512B blocks).

Decodes the CHAdeMO H-messages in time order so the cable-check / precharge /
charge / shutdown voltage+current+error evolution is visible:
  H100 0x100 maxV/cap   H101 0x101 minV/curr   H102 0x102 charge status
  H108 0x108 EV status  H109 0x109 EV status2  H110 0x110 EVSE status
H102 layout (confirmed): byte0=ChargingCurrentRequest[A], bytes1-2=battery
voltage (LE, V), byte5=error flags (0x80 VoltageDeviation, 0x08 CurrentDeviation).
chan f9/fa = the two CAN directions, ff = adapter internal.

Usage: nix-shell -p python3 --run 'python3 analyze43.py <LOGS.BIN> <SessionIDhex> [--all]'
"""
import sys, struct, collections

data = open(sys.argv[1], 'rb').read()
n = len(data)
want = sys.argv[2].lower()
show_all = '--all' in sys.argv

def walk():
    off = 0
    while off + 8 <= n:
        if data[off] == 0xFF:
            off += 1; continue
        ts, ln, typ, ck = struct.unpack_from('<IHBB', data, off)
        if ln == 0 or ln > 1024 or off + 8 + ln > n:
            off += 1; continue
        yield off, ts, typ, data[off + 8: off + 8 + ln]
        off += 8 + ln

# find ts window of the wanted session from EXI records
t_lo, t_hi = None, None
for off, ts, typ, p in walk():
    if typ in (2, 3, 5):
        i = p.find(b'\x01\xfe\x80\x01')
        if i < 0 or i + 8 > len(p):
            continue
        plen = struct.unpack_from('>I', p, i + 4)[0]
        body = p[i + 8: i + 8 + plen]
        if body[:2] == b'\x80\x9a' and len(body) >= 7 and body[3:7].hex() == want:
            t_lo = ts if t_lo is None else min(t_lo, ts)
            t_hi = ts if t_hi is None else max(t_hi, ts)
if t_lo is None:
    print(f"SessionID {want} not found"); sys.exit(1)
print(f"=== SessionID {want}: EXI ts {t_lo}..{t_hi}; CAN window {t_lo-2}..{t_hi+25} ===")

ERR = {0x80: 'VoltageDeviation', 0x40: 'bit6', 0x20: 'bit5', 0x10: 'bit4',
       0x08: 'CurrentDeviation', 0x04: 'bit2', 0x02: 'bit1', 0x01: 'bit0'}
def errstr(b):
    return '|'.join(v for k, v in ERR.items() if b & k) or '-'

rows = []
for off, ts, typ, p in walk():
    if typ != 6 or ts < t_lo - 2 or ts > t_hi + 25:
        continue
    for so in range(0, len(p) - 15, 16):
        sts, idf = struct.unpack_from('<II', p, so)
        d = p[so + 8: so + 16]
        msg = idf & 0xFF; chan = (idf >> 8) & 0xFF
        if (idf >> 16) != 0x1fff:
            continue
        rows.append((ts, sts, chan, msg, d))
rows.sort(key=lambda r: (r[0], r[1]))

print(f"  {len(rows)} CAN sub-records in window")
print("  [blk_ts +ms] chan id  decoded")
for ts, sts, chan, msg, d in rows:
    cid = 0x100 + msg
    if msg == 0x02:  # H102 charge status
        cur = d[0]; vol = d[1] | (d[2] << 8); err = d[5]
        line = f"H102 cur_req={cur:3d}A battV={vol:4d}V err5=0x{err:02x}({errstr(err)}) b6=0x{d[6]:02x} b7=0x{d[7]:02x}"
    elif msg == 0x10:  # H110 EVSE status
        line = f"H110 EVSE status data={d.hex(' ')}"
    elif msg == 0x00:  # H100
        v = d[4] | (d[5] << 8)
        line = f"H100 maxV={v:4d}V data={d.hex(' ')}"
    elif msg == 0x01:  # H101
        line = f"H101 minV/curr data={d.hex(' ')}"
    elif msg == 0x08:  # H108
        v = d[1] | (d[2] << 8); tgt = d[4] | (d[5] << 8)
        line = f"H108 EV status battV={v}V target={tgt}V data={d.hex(' ')}"
    elif msg == 0x09:  # H109
        line = f"H109 EV status2 data={d.hex(' ')}"
    else:
        line = f"H{msg:02x} data={d.hex(' ')}"
    if not show_all and msg not in (0x02, 0x10, 0x08, 0x00):
        continue
    print(f"  [{ts:>6} +{sts:>6}] {chan:#04x} 0x{cid:03x} {line}")