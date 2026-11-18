#!/usr/bin/env python3
"""Map firmware epochs + charge sessions in EVCC_<MAC>_LOGS.BIN by FILE OFFSET.

The log is a 4KB-page ring buffer; ts is a per-epoch counter that overlaps across
firmware upgrades, so chronology must come from file-offset (write) order, not ts.
Version banners (EVCCx.y[02.01.Cxxx], e.g. EVCC1.0 C009 / EVCC2.9 C013) and
UPGRADE:[size]ver date strings delimit epochs. This script:
  1. raw-scans banners / UPGRADE / RESET markers with offsets (true write order);
     version-bearing markers form epoch boundaries (the record walk can desync in
     the ring buffer, so epochs are attributed by marker offset, not parsed banners)
  2. walks records in file order, tagging each with its epoch + SessionID
  3. prints a compact event timeline (banners, SLAC, SessionSetup, CHAdeMO state
     milestones, errors, shutdown) and a per-session summary
  4. with --tail OFFSET, dumps every record at/after OFFSET verbatim (C013 region)

Read-only.
Usage: nix-shell -p python3 --run 'python3 analyze42.py <LOGS.BIN> [--tail 0x23000]'
"""
import sys, struct, re, collections, bisect

path = sys.argv[1]
data = open(path, 'rb').read()
n = len(data)
tail = None
if '--tail' in sys.argv:
    tail = int(sys.argv[sys.argv.index('--tail') + 1], 0)

# ---- 1. raw epoch markers in write order ----
print("=== EPOCH MARKERS (raw scan, file-offset = write order) ===")
marks = []
for m in re.finditer(rb'EVCC\d+\.\d+\[02\.01\.C\d{3}\]|EVCC\[01\.00\.T\d{3}\]|UPGRADE:\[\d+\][^\x00]{0,40}|RESET\[\d+\] at \d+', data):
    s = m.group().decode('latin1', 'replace')
    marks.append((m.start(), s))
for off, s in marks:
    print(f"  f+0x{off:06x}: {s}")

# epoch boundaries from version-bearing markers (banners + UPGRADE), in write order
boundaries = []
for off, s in marks:
    mv = re.search(r'(C\d{3}|T\d{3})', s)
    if mv:
        boundaries.append((off, mv.group(1)))
boundaries.sort()
boffs = [b[0] for b in boundaries]

def epoch_at(off):
    i = bisect.bisect_right(boffs, off) - 1
    return boundaries[i][1] if i >= 0 else '?'

# ---- record walk ----
def walk():
    off = 0
    while off + 8 <= n:
        if data[off] == 0xFF:
            off += 1
            continue
        ts, ln, typ, ck = struct.unpack_from('<IHBB', data, off)
        if ln == 0 or ln > 1024 or off + 8 + ln > n:
            off += 1
            continue
        yield off, ts, typ, data[off + 8: off + 8 + ln]
        off += 8 + ln

def exi(p):
    i = p.find(b'\x01\xfe\x80\x01')
    if i < 0:
        return None
    if i + 8 > len(p):
        return None
    plen = struct.unpack_from('>I', p, i + 4)[0]
    body = p[i + 8: i + 8 + plen]
    sid = None
    if body[:2] == b'\x80\x9a' and len(body) >= 7 and body[2] in (1, 2):
        sid = body[3:7].hex()
    return body, sid

# ---- 2/3. epoch-tagged event timeline ----
print("\n=== EVENT TIMELINE (file order; epoch tagged) ===")
sess = collections.OrderedDict()
for off, ts, typ, p in walk():
    epoch = epoch_at(off)
    if typ == 4 and p.endswith(b'\0'):
        t = p.rstrip(b'\0').decode('latin1')
        key = ('UPGRADE' in t or 'RESET[' in t or 'Power up' in t or 'system init' in t
               or 'Passive reset' in t or 'EVCC' in t or '#SLAC' in t or '#SDP' in t
               or '#TCP' in t or 'stm :' in t or 'stm:' in t or 'Error' in t or 'error' in t
               or 'Shutdown' in t or 'shutdown' in t or 'PreCharge' in t or 'Precharge' in t
               or 'CableCheck' in t or 'Cablecheck' in t or 'cablecheck' in t or 'BatteryCharge' in t
               or 'DEEP SLEEP[' in t or 'TargetBatteryVoltage' in t or 'outvol' in t
               or 'AvailableOutputVoltage' in t or 'PresentOutputVoltage' in t or 'MaximumBatteryVoltage' in t)
        if key:
            print(f"  f+0x{off:06x} [{ts:>7}] {epoch:5s} t4: {t}")
    elif typ in (2, 3, 5):
        e = exi(p)
        if e:
            body, sid = e
            h = body[:2]
            if h == b'\x80\x00':
                print(f"  f+0x{off:06x} [{ts:>7}] {epoch:5s} t{typ}: SessionSetupReq (EVCCID)")
            elif h == b'\x80\x40':
                print(f"  f+0x{off:06x} [{ts:>7}] {epoch:5s} t{typ}: SessionSetupRes {body.hex(' ')}")
            if sid:
                sess.setdefault(sid, {'offs': [], 'ts': [], 'n': 0})
                sess[sid]['offs'].append(off)
                sess[sid]['ts'].append(ts)
                sess[sid]['n'] += 1

print("\n=== SESSIONS BY SessionID (file-offset range = chronology) ===")
for sid, d in sess.items():
    print(f"  SessionID {sid}: epoch={epoch_at(min(d['offs']))} n={d['n']} "
          f"f+0x{min(d['offs']):06x}..0x{max(d['offs']):06x} ts {min(d['ts'])}..{max(d['ts'])}")

# ---- 4. verbatim tail dump ----
if tail is not None:
    print(f"\n=== VERBATIM RECORDS f+0x{tail:06x}..end ===")
    for off, ts, typ, p in walk():
        if off < tail:
            continue
        if typ == 4 and p.endswith(b'\0'):
            print(f"  f+0x{off:06x} [{ts:>7}] t4: {p.rstrip(chr(0).encode()).decode('latin1')}")
        else:
            e = exi(p) if typ in (2, 3, 5) else None
            extra = ''
            if e:
                body, sid = e
                extra = f" sid={sid} hdr={body[:2].hex()} body={body[:28].hex(' ')}"
            print(f"  f+0x{off:06x} [{ts:>7}] t{typ} {len(p)}B:{extra} {p[:40].hex(' ')}")