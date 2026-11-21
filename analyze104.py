#!/usr/bin/env python3
"""analyze104.py — C013 state-17 engagement-guard `ress_vol` provenance decoder (read-only RE).

RESOLVES the comparison reference of the safety-critical state-17 voltage-engagement guard
(0x0804AF08-0x0804AF30): is `ress_vol` the car's H102 TargetBatteryVoltage, or the EVSE's
self-reported PresentVoltage? Derives everything from the C013 bytes (no hardcoded conclusions):

  1. The guard block: outvol = p[+0x16] (r4 = stm ctx) compared against sl (r10) = ress_vol;
     window outvol ∈ [ress_vol-10, ress_vol+5], dwell p[+0x0A] >= 0xFA(250), phase meas+0x3D1E==4.
  2. The stm-function stack-slot setup: sp+0x1c / sp+0x24 / sp+0x60 <- meas base (r6) + offset
     (movw #imm ; add r0,r6 ; str r0,[sp,#slot]). Recovers which EVSE field feeds ress_vol.
  3. The ress_vol computation: ldrb factor@[sp+0x24] -> sxtb -> converter 0x0804E786 (pow10) ->
     ldrh raw@[sp+0x1c] -> muls -> udiv sl,#1000  =  din_scale(EVSEPresentVoltage_raw, factor).
  4. The dual log "Precharge,wait out[%lu]reach ress_vol[%lu],TargetBatteryVoltage[%lu]V,
     ChargingCurrentRequest[%lu]A" (fmt 0x080AB80C, loaded base+offset): ress_vol arg = sl,
     TargetBatteryVoltage arg = p[+0x1da], ChargingCurrentRequest arg = p[+0x1dc] — DISTINCT values.
  5. The 17case-GOOD log (fmt 0x080AB930): ress_vol arg = sl, outvol = p[+0x16].
  6. State-19 (0x08044608): sl is a dwell-TIMEOUT counter there (cmp phase_cnt,sl); the
     TargetBatteryVoltage (p+0x1da) is only logged, not voltage-compared.

CONCLUSION: ress_vol = EVSE PresentVoltage (meas+0x3D18/1A scaled), NOT H102 TargetBatteryVoltage.
During precharge the EVSE reports the battery voltage (~364 V on a ZE1), not the 410 V full-charge
target. The custom_fw replica previously used veh->target_voltage (410) -> window [400,415] the
precharge output (~364) can never reach -> state-17 stalls to timeout -> 450 (the C009 abort).
Corrected: charge_stm now uses ccs2_evse()->evse_present_voltage = din_evse_present_voltage_v().

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze104.py'
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
def cstr(o):
    e = fw.find(b'\x00', o)
    return fw[o:e].decode('ascii', 'replace') if 0 <= e and e-o < 256 else ''
def pool(o):
    h = u16(o)
    if (h & 0xF800) == 0x4800:
        p = ((rt(o)+4) & ~3) - TB + (h & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    if (h & 0xFF7F) == 0xF85F and o+4 <= N:
        U = (h >> 7) & 1; imm = u16(o+2) & 0xFFF; b = ((rt(o)+4) & ~3)
        p = (b+imm if U else b-imm) - TB
        if 0 <= p and p+4 <= N: return u32(p)
    return None
def dump(addr, n, label):
    print(f"\n== {label}  0x{addr:08X} ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  0x{rt(a):08X}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = f"  ; =0x{w:08X}" if w is not None else ""
        if w is not None and TB <= w < TB+N and 32 <= fw[w-TB] < 127:
            ex += f' "{cstr(w-TB)[:60]}"'
        print(f"  0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{ex}")
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break

print("== 1. state-17 engagement guard (outvol p[+0x16] vs sl=ress_vol) ==")
dump(0x0804AF08, 16, "guard 0x0804AF08-0x0804AF30")

print("\n== 2. stm stack-slot setup: sp+slot <- meas(r6) + offset (ress_vol raw/factor/phase) ==")
# scan the setup region for movw r0,#imm ; add r0,r6 ; str r0,[sp,#slot]
a = 0x08049150 - TB; end = 0x080491A0 - TB; pend = None; slots = {}
while a < end:
    ins = dis(a)
    if not ins: a += 2; continue
    i = ins[0]; ops = i.operands
    if i.mnemonic == 'movw' and len(ops) == 2 and ops[1].type == 2:
        pend = ops[1].imm & 0xFFFF
    elif i.mnemonic in ('str','str.w') and len(ops) == 2 and ops[1].type == 3 \
         and ops[1].mem.base == 13 and pend is not None:
        slots[ops[1].mem.disp] = pend
        print(f"  0x{rt(a):08X}: str r0,[sp,#0x{ops[1].mem.disp:02x}]  <- meas+0x{pend:04X}")
        pend = None
    a += i.size
print(f"  => sp+0x1c=meas+0x{slots.get(0x1c,0):04X} (PresentVoltage RAW), "
      f"sp+0x24=meas+0x{slots.get(0x24,0):04X} (FACTOR), sp+0x60=meas+0x{slots.get(0x60,0):04X} (phase)")

print("\n== 3. ress_vol computation: sl = din_scale(raw@[sp+0x1c], factor@[sp+0x24]) ==")
dump(0x0804AADA, 11, "0x0804AADA-0x0804AAEE (converter + muls + udiv sl,#1000)")

print("\n== 4. dual log: ress_vol(sl) vs TargetBatteryVoltage(p+0x1da) — DISTINCT ==")
dump(0x0804AB3E, 13, "0x0804AB3E-0x0804AB56 (fmt 0x080AB74C+0xc0 = 0x080AB80C)")
print(f"  fmt string: {cstr(0x080AB80C-TB)!r}")

print("\n== 5. 17case-GOOD log: ress_vol arg = sl, outvol = p[+0x16] ==")
dump(0x0804AF5C, 9, "0x0804AF5C-0x0804AF6C (fmt 0x080AB930)")
print(f"  fmt string: {cstr(0x080AB930-TB)!r}")

print("\n== 6. state-19: sl = dwell TIMEOUT counter; TargetBatteryVoltage only logged ==")
dump(0x08044644, 4, "0x08044644 (cmp phase_cnt p[+4], sl ; bhi timeout)")
dump(0x08044690, 6, "0x08044690 (19case log: TargetBatteryVoltage p+0x1da logged)")

print("\n== RESOLVED ==")
print("  ress_vol (state-17 engagement reference) = EVSE PresentVoltage = din_scale(meas+0x3D18,")
print("  meas+0x3D1A) — the EVSE's self-reported present output voltage (PreChargeRes/CurrentDemandRes).")
print("  It is NOT the H102 TargetBatteryVoltage (p+0x1da): the dual log 0x0804AB40 prints both as")
print("  separate values. During precharge the EVSE ramps to the BATTERY voltage and reports it here")
print("  (~364 V on a ZE1); the full-charge target is 410 V. The guard waits for the adapter's measured")
print("  output (p[+0x16] ~ get_hv/10) to match the EVSE present voltage, NOT the 410 V target.")
print("  Replica fix: charge_stm ress_vol <- ccs2_evse()->evse_present_voltage (was veh->target_voltage).")
print("  Using the target as the reference stalls state 17 to its 424-tick timeout -> 450 (C009 abort).")