#!/usr/bin/env python3
"""Decode the raw car<->charger records in EVCC_<MAC>_LOGS.BIN.

Focus: the binary record types the text-line diff never covered —
  t2/t3 = DIN70121 V2G EXI request/response (V2GTP 01 fe 80 01 + u32 len + EXI)
  t5    = EXI shutdown / session-stop exchanges
  t6    = 512-byte CHAdeMO CAN blocks (16-byte sub-records: u32 ts_ms | u32 idfield | 8B data)

Sessions are keyed by the EXI SessionID embedded after the 80 9a 01/02 header,
so identical wording from different charge attempts is still distinguished.
Read-only.

Usage: nix-shell -p python3 --run 'python3 analyze40.py <LOGS.BIN> [--last N]'
"""
import sys, struct, collections

data = open(sys.argv[1], 'rb').read()
n = len(data)

# ---- parse records (same empirical format as analyze37) ----
recs = []
off = 0
while off + 8 <= n:
    if data[off] == 0xFF:
        while off < n and data[off] == 0xFF:
            off += 1
        continue
    ts, ln, typ, ck = struct.unpack_from('<IHBB', data, off)
    if ln == 0 or ln > 1024 or off + 8 + ln > n:
        off += 1
        continue
    recs.append((ts, typ, data[off + 8: off + 8 + ln]))
    off += 8 + ln

# ---- key EXI records by SessionID; t2/t3/t5 carry V2GTP ----
def exi_info(p):
    if p[:4] != b'\x01\xfe\x80\x01':
        return None
    plen = struct.unpack_from('>I', p, 4)[0]
    body = p[8:8 + plen]
    sid = None
    # SessionID appears as 4 bytes after the 80 9a 01/02 message header.
    # 80 9a 00 is ServiceDiscoveryReq (pre-session, no SessionID) — skip it.
    if body[:2] == b'\x80\x9a' and len(body) >= 7 and body[2] in (1, 2):
        sid = body[3:7].hex()
    return plen, body, sid

sessions = collections.OrderedDict()
for ts, typ, p in recs:
    if typ in (2, 3, 5):
        info = exi_info(p)
        if info and info[2]:
            sessions.setdefault(info[2], []).append((ts, typ, info[1]))

print(f"=== {len(recs)} records parsed; {len(sessions)} EXI sessions keyed by SessionID ===")
for sid, msgs in sessions.items():
    t0 = min(m[0] for m in msgs); t1 = max(m[0] for m in msgs)
    print(f"  SessionID {sid}: {len(msgs)} EXI msgs, ts {t0}..{t1}")

# ---- pick the last session (highest ts) ----
last_sid = max(sessions, key=lambda s: max(m[0] for m in sessions[s]))
last_t0 = min(m[0] for m in sessions[last_sid])
print(f"\n=== LAST SESSION  SessionID={last_sid}  (starts ts {last_t0}) ===")

# ---- EXI message sequence for the last session ----
print("\n-- DIN70121 EXI sequence (t3=EVCC->EVSE req, t2=EVSE->EVCC res, t5=shutdown) --")
HDR = {b'\x80\x00': 'SessionSetupReq', b'\x80\x40': 'SessionSetupRes'}
for ts, typ, p in recs:
    if typ not in (2, 3, 5) or ts < last_t0 - 2:
        continue
    info = exi_info(p)
    if not info:
        # t5 shutdown records have a 4-byte prefix before V2GTP
        i = p.find(b'\x01\xfe\x80\x01')
        if i < 0:
            continue
        plen = struct.unpack_from('>I', p, i + 4)[0]
        body = p[i + 8: i + 8 + plen]
        tag = f"t{typ} shutdown prefix={p[:i].hex(' ')}"
    else:
        plen, body, sid = info
        tag = f"t{typ}"
    h = body[:2]
    name = HDR.get(h, '')
    if h == b'\x80\x9a':
        name = f"msg hdr 80 9a {body[2]:02x}"
    print(f"  [{ts:>6}] {tag:14s} len={plen:3d} {name:18s} {body[:24].hex(' ')}")

# ---- CHAdeMO CAN blocks (t6) for the last session ----
print("\n-- CHAdeMO CAN frames (t6 512B blocks, 16-byte sub-records) --")
H = {0x00: 'H100 maxV/cap', 0x01: 'H101 minV/curr', 0x02: 'H102 charge status',
     0x08: 'H108 EV status', 0x09: 'H109 EV status2', 0x10: 'H110 EVSE status',
     0x03: 'H103', 0x04: 'H104', 0x05: 'H105', 0x06: 'H106', 0x07: 'H107',
     0x0a: 'H10a', 0x0b: 'H10b', 0x0c: 'H10c', 0x0d: 'H10d', 0x0e: 'H10e', 0x0f: 'H10f',
     0x11: 'H111', 0x12: 'H112'}
seen = collections.Counter()
for ts, typ, p in recs:
    if typ != 6 or ts < last_t0 - 2:
        continue
    for so in range(0, len(p) - 15, 16):
        sts, idf = struct.unpack_from('<II', p, so)
        d = p[so + 8: so + 16]
        msg = idf & 0xFF
        chan = (idf >> 8) & 0xFF
        if (idf >> 16) != 0x1fff:
            continue
        seen[(chan, msg)] += 1
        if seen[(chan, msg)] <= 2:
            print(f"  [blk {ts:>6} +{sts:>6}ms] id=0x{0x100+msg:03x} chan={chan:#04x} "
                  f"{H.get(msg,'?'):18s} data={d.hex(' ')}")
print("\n  CAN frame counts (chan, msgnum):")
for (chan, msg), c in sorted(seen.items()):
    print(f"    chan={chan:#04x} id=0x{0x100+msg:03x} {H.get(msg,'?'):18s} x{c}")