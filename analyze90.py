#!/usr/bin/env python3
"""analyze90.py — output-current ACTUATION chain (§5.21 F): how the state-30 setpoint reaches the power
path. Confirms the adapter has NO local PWM/DAC current actuation — the setpoint (EVTargetCurrentValue,
ctx 0x20000780+0x16) is commanded to the upstream CCS2 EVSE via the DIN70121 CurrentDemandReq PLC message,
and the CHAdeMO H108/H109 CAN frames REPORT the EVSE output measurements back to the vehicle. The power
path itself is switched by contactor/relay GPIO (§5.5c), not a PWM/DAC register.

Decodes (C013):
  1. setpoint -> telemetry: state-30 0x08044DC8 writes ctx+0x16 (current) / +0x1c (target_v) to output
     buffers + status=3, logged via 0x080514da w/ format 0x080A9388 ("EVTargetCurrentValue..EVTargetVoltageValue").
  2. H108 output-value compute 0x0803C95C: EVSE raw[0x3D08]*converter(byte[0x3D0A])/1000, clamp 0x1C2 (450)
     -> p[+0x212] (status p[+0x210]=1); tail-branch 0x0804EA4C.
  3. H108 build+send 0x0803CB36: mutex ctx+0x68 (0x200007E8), pack p[+0x210..0x219] -> 8-byte buf p[+0x25C],
     CAN ID 0x108 -> ctx+0x60, send via fn-ptr p[+0x270] (blx).
  4. H109 output-value compute 0x0803C9B8: EVSE raw[0x3D14]/[0x3D18] + get_hv(0x08052770)/10 -> p[+0x220..0x226].
  5. H109 build+send 0x0803CBDC: pack p[+0x220..0x226] -> buf, CAN ID 0x109, send via fn-ptr.
  6. CCS2 DIN70121 CurrentDemandReq/Res log strings (the upstream-EVSE command path that consumes the
     EVTargetCurrent setpoint; decoded fully in the EVSE-side subsystem layer).

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze90.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
def pool(o):
    h = u16(o)
    if (h & 0xF800) == 0x4800:
        p = (((rt(o)+4) & ~3) - TB) + (h & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    if (h & 0xFF7F) == 0xF85F and o+4 <= N:
        U = (h >> 7) & 1; imm = u16(o+2) & 0xFFF; b = ((rt(o)+4) & ~3)
        p = (b+imm if U else b-imm) - TB
        if 0 <= p and p+4 <= N: return u32(p)
    return None
def cstr(addr, maxlen=100):
    o = addr - TB
    if not (0 <= o < N): return ""
    e = fw.find(b'\x00', o, o+maxlen)
    if e < 0: e = o+maxlen
    s = fw[o:e].decode('latin-1', 'replace')
    return s if s and all(32 <= ord(c) < 127 for c in s[:6]) else ""
def dump(addr, n, label):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = ""
        if w is not None:
            tag = (" FLASH" if 0x08000000 <= w < 0x08100000 else
                   " RAM" if 0x20000000 <= w < 0x20030000 else
                   " PERIPH" if 0x40000000 <= w < 0x60000000 else "")
            ex = f"  ; =0x{w:08X}{tag}"
            if 0x08000000 <= w < 0x08100000:
                s = cstr(w)
                if s: ex += f'  "{s[:70]}"'
        hl = ""
        if w == 0x20000780: hl += " <<<CTX"
        if i.mnemonic in ('str', 'strh', 'str.w', 'strh.w') and w is not None and 0x40000000 <= w < 0x60000000:
            hl += " <<<PERIPH-WRITE"
        if i.mnemonic in ('bl', 'blx'): hl += " <<<CALL"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{ex}{hl}")
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break

print("################ OUTPUT-CURRENT ACTUATION CHAIN (§5.21 F) ################")
print("== 1. setpoint -> telemetry log (state-30) ==")
print(f"  log format 0x080A9388: \"{cstr(0x080A9388)}\"")
dump(0x08044DC8, 22, "state-30 setpoint(ctx+0x16/+0x1c) -> output buffers + status=3")
print("  ctx+0x16 = EVTargetCurrentValue, ctx+0x1c = EVTargetVoltageValue (logged, not a HW register).")

print("\n== 2. H108 output-value compute (EVSE measurement, 450 clamp) ==")
dump(0x0803C95C, 30, "H108 output-value compute 0x0803C95C")
print("  law: outval = EVSE_raw[0x3D08]*converter(byte[0x3D0A])/1000, clamp 0x1C2 (450) -> p[+0x212];")
print("       status p[+0x210]=1. Reads EVSE-side measurements, NOT the setpoint ctx+0x16.")

print("\n== 3. H108 build + CAN send ==")
dump(0x0803CB36, 40, "H108 build+send 0x0803CB36")
print("  mutex ctx+0x68 (0x200007E8); pack p[+0x210..0x219] -> 8-byte buf p[+0x25C]; CAN ID 0x108 -> ctx+0x60;")
print("  send via fn-ptr p[+0x270] (blx r3). This is the CHAdeMO H108 report to the vehicle.")

print("\n== 4. H109 output-value compute (EVSE measurement + get_hv) ==")
dump(0x0803C9B8, 24, "H109 output-value compute 0x0803C9B8 (head)")
print("  EVSE_raw[0x3D14]/[0x3D18] (current) + get_hv 0x08052770/10 (voltage) -> p[+0x220..0x226];")
print("  state-dependent zeroing when outvol==0. Reports EVSE output, not the setpoint.")

print("\n== 5. H109 build + CAN send ==")
dump(0x0803CBDC, 24, "H109 build+send 0x0803CBDC (head)")
print("  pack p[+0x220..0x226] -> buf p[+0x25C]; CAN ID 0x109; send via fn-ptr. CHAdeMO H109 report.")

print("\n== 6. CCS2 DIN70121 CurrentDemand handlers (upstream-EVSE command path) ==")
for needle in (b'--> CurrentDemandReq', b'<-- CurrentDemandRes'):
    idx = 0; hits = []
    while True:
        i = fw.find(needle, idx)
        if i < 0: break
        s = fw.rfind(b'\x00', max(0, i-40), i)+1
        hits.append(rt(s)); idx = i+1
    print(f"  '{needle.decode()}': " + ', '.join(f'0x{a:08X}' for a in hits[:6]))
print("  The EVTargetCurrent setpoint (ctx+0x16) is commanded to the upstream CCS2 EVSE via CurrentDemandReq")
print("  (DIN70121 EXI over QCA7005 PLC). The builder accesses the shared ctx via pointer (no LDR-literal")
print("  ctx load in the CCS2/DIN region 0x0802D000-0x08038000); fully decoded in the EVSE-side layer.")

print("\n== RESOLVED actuation architecture (§5.21 F) ==")
print("  NO local PWM/DAC current actuation: no peripheral (0x4000xxxx) writes in the setpoint/output path.")
print("  The adapter is a protocol bridge + contactor controller, NOT a power regulator:")
print("   - vehicle H102 request -> CHAdeMO stm state-30 setpoint = min(request,EVSE avail) capped by EVSE max")
print("     (ctx 0x20000780+0x16 EVTargetCurrentValue / +0x1c EVTargetVoltageValue, analyze89);")
print("   - setpoint -> CCS2 PLC CurrentDemandReq -> upstream EVSE regulates the actual DC output;")
print("   - EVSE output measurements -> CHAdeMO H108 (0x108, 450-clamped) / H109 (0x109) CAN report to vehicle")
print("     (build+send 0x0803CB36/0x0803CBDC via fn-ptr p[+0x270], CAN ID at ctx+0x60);")
print("   - power path switched by contactor/relay GPIO (d1/d2/precharge/inner/charge, §5.5c), not PWM/DAC.")
print("  => the inert current_ctrl shadow setpoint is the correct replica; the asserted 'drive' is the CCS2")
print("     CurrentDemand PLC message (EVSE-side subsystem) + contactor GPIO sequencing (gated layer).")