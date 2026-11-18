#!/usr/bin/env python3
"""PROOF TEST: was EVCC_<MAC>_LOGS.BIN produced by THIS firmware.bin?

The device's log lines are rendered printf output. firmware.bin holds the format
templates (e.g. 'UPGRADE:[%u]%c%c%c%c%c.%c%c%c%c 20%02X-...') and literal strings
(e.g. '#SLAC: Matching failed', typo 'EVSE authoried'). For every distinct log line:
  * EXACT  — the literal line occurs verbatim in firmware.bin, or
  * TEMPLATE — the line full-matches a firmware format string converted to a regex.
Lines that match NEITHER would indicate a different firmware. Read-only.

Usage: nix-shell -p python3 --run 'python3 analyze39.py firmware.bin EVCC_..._LOGS.BIN'
"""
import sys, struct, re, collections

fw = open(sys.argv[1], 'rb').read()
log = open(sys.argv[2], 'rb').read()
BASE = 0x08020000
nfw, nlog = len(fw), len(log)

# ---- 1. collect distinct rendered text lines from the log (type-4 records) ----
lines = collections.Counter()
off = 0
while off + 8 <= nlog:
    if log[off] == 0xFF:
        while off < nlog and log[off] == 0xFF: off += 1
        continue
    ts, ln, typ, ck = struct.unpack_from('<IHBB', log, off)
    if ln == 0 or ln > 1024 or off + 8 + ln > nlog:
        off += 1; continue
    payload = log[off + 8: off + 8 + ln]
    if typ == 4 and payload.endswith(b'\0'):
        t = payload[:-1].decode('latin1').strip()
        if t: lines[t] += 1
    off += 8 + ln

# ---- 2. firmware strings: literals vs format templates ----
fw_strings = []   # (offset, text)
for m in re.finditer(rb'[\x20-\x7e]{4,}', fw):
    fw_strings.append((m.start(), m.group().decode('latin1')))
literals = {s: o for o, s in fw_strings if '%' not in s}
formats  = [(o, s) for o, s in fw_strings if '%' in s]

SPEC = re.compile(r'%([-+ #0]*)(\d*)(?:\.(\d+))?(?:ll|l|hh|h|z|j|t)?([diuxXocsfgeE%])')
def fmt_to_regex(fmt):
    fmt = fmt.replace('[%t]', '\x00TS\x00').replace('%t', '\x00TS\x00')
    out = []; i = 0
    while i < len(fmt):
        if fmt[i] == '\x00':
            j = fmt.index('\x00', i + 1)
            out.append(r'(?:\[\d{2}:\d{2}:\d{2}\.\d+\])?'); i = j + 1; continue
        m = SPEC.match(fmt, i)
        if m:
            conv = m.group(4); width = m.group(2)
            if conv == '%': out.append('%')
            elif conv in 'diu': out.append(r'-?\d+(?:\.\d+)?')
            elif conv in 'xX': out.append('[0-9a-fA-F]{%s}' % width if width else '[0-9a-fA-F]+')
            elif conv == 'c': out.append('.')
            elif conv == 's': out.append('.*?')
            elif conv in 'fgeE': out.append(r'-?\d+(?:\.\d+)?')
            i = m.end(); continue
        out.append(re.escape(fmt[i])); i += 1
    return ''.join(out)

def specificity(s):
    return len(SPEC.sub('', s.replace('[%t]', '').replace('%t', '')))
fmt_regex = [(o, s, re.compile(fmt_to_regex(s.strip()))) for o, s in formats]
fmt_regex.sort(key=lambda t: -specificity(t[1]))   # try distinctive templates before %s%s catch-alls
TS = re.compile(r'^\[\d{2}:\d{2}:\d{2}\.\d+\]\s*')

exact, templ, unmatched = [], [], []
for L, cnt in lines.items():
    Ld = TS.sub('', L)
    hit = None
    for cand in (L, Ld):
        if cand in literals:
            hit = ('EXACT', literals[cand], cand); break
        b = cand.encode('latin1')
        k = fw.find(b)
        if k >= 0 and len(b) >= 6:
            hit = ('EXACT-sub', k, cand); break
    if not hit:
        for o, s, rx in fmt_regex:
            if specificity(s) == 0:        # %s%s / %s catch-alls match anything -> NOT evidence
                continue
            for cand in (L, Ld):
                if rx.fullmatch(cand):
                    hit = ('TEMPLATE', o, s); break
            if hit: break
    if not hit:
        unmatched.append((L, cnt))
    elif hit[0].startswith('EXACT'):
        exact.append((L, cnt, hit[1], hit[2]))
    else:
        templ.append((L, cnt, hit[1], hit[2]))

print(f"=== distinct log text lines: {len(lines)}  (total records {sum(lines.values())}) ===")
print(f"=== firmware strings: {len(literals)} literal, {len(formats)} format templates ===")
print(f"\nMATCH SUMMARY:  EXACT literal = {len(exact)}   TEMPLATE rendered = {len(templ)}   UNMATCHED = {len(unmatched)}")
print(f"  -> {len(exact)+len(templ)}/{len(lines)} distinct log lines accounted for by firmware.bin "
      f"({100*(len(exact)+len(templ))//max(1,len(lines))}%)")

print(f"\n=== EXACT literal matches ({len(exact)}) — verbatim in BOTH files ===")
for L, cnt, o, cand in sorted(exact, key=lambda x: x[2]):
    print(f"  f+0x{o:06x} 0x{BASE+o:08x}  (x{cnt})  {L}")

print(f"\n=== TEMPLATE matches ({len(templ)}) — log line renders a firmware format string ===")
for L, cnt, o, s in sorted(templ, key=lambda x: x[2]):
    print(f"  f+0x{o:06x}  (x{cnt})")
    print(f"      FW : {s}")
    print(f"      LOG: {L}")

print(f"\n=== NOT specifically matched to C009 ({len(unmatched)}) — pre-upgrade C002 / modem runtime data ===")
print("    (these render only via the generic %s%s logger wrapper; no distinctive C009 string)")
for L, cnt in sorted(unmatched, key=lambda x: -x[1]):
    print(f"  (x{cnt})  {L}")

print("\n=== supplementary: longest VERBATIM substring of each log line in firmware.bin ===")
print("    (C002 & C009 share many substrings, so this over-counts; decisive proof = EXACT + specific TEMPLATE + typos)")
core_ok = 0; core_fail = []; distinctive = []
for L in lines:
    best = ''; besto = -1; found = False
    for length in range(len(L), 9, -1):           # longest common substring, min 10 chars
        for i in range(0, len(L) - length + 1):
            k = fw.find(L[i:i + length].encode('latin1'))
            if k >= 0:
                best = L[i:i + length]; besto = k; found = True; break
        if found: break
    if found:
        core_ok += 1
        if any(t in best for t in ('authoried', 'swithc', 'charging end', 'UPGRADE', 'GET_AD_CPD',
                                   'DIN70121', 'Cablecheck', 'connector plugin', 'EmergencyShutDown')):
            distinctive.append((L, best, besto))
    else:
        core_fail.append(L)
print(f"  {core_ok}/{len(lines)} log lines contain a >=10-char VERBATIM substring of firmware.bin")
print(f"  lines with NO >=10-char verbatim core: {len(core_fail)}")
for L in core_fail:
    print(f"    !! {L}")
print("  distinctive verbatim cores (message text literally present in firmware.bin):")
for L, best, o in distinctive:
    print(f"    f+0x{o:06x} 0x{BASE+o:08x}: {best!r}")
    print(f"        full log line: {L}")

print("\n=== distinctive typo fingerprints (shared misspellings = forensic ID) ===")
for typo in [b'authoried', b'swithc', b'Evse', b'Evcc', b'CHAdeMO', b'CCS2CHAdeMO', b'GET_AD_CPD',
             b'bms_shutdown', b'GBT_STATE_OCCURRENCE', b'KM-CCS2CHAdeMO']:
    infw = fw.count(typo); inlog = log.count(typo)
    print(f"  {typo.decode():22s} firmware.bin={infw:3d}   LOGS.BIN={inlog:3d}")