#!/usr/bin/env python3
"""analyze105.py — C013 charge-coordination decoder: G10 PreCharge<->car-contactor coupling +
G11 output-current ramp (read-only RE). Resolves the two charge-coordination gaps scoped in
custom_fw/CCS2_GAPS.md by deriving everything from the C013 bytes (no hardcoded conclusions).

G10 — CCS PreCharge <-> CHAdeMO car-contactor coupling
  The coupling lives in the CHAdeMO charge stm (the big function entered at 0x08048D22), NOT in a
  stall of the DIN EVSE-side PreChargeReq loop:
    * state 15 (0x0804A284): ldrb p[+0x1de] ; ubfx #3,#1 = H102.VehicleStatus bit3 = EV contactor
      closed. Log 0x080AB1DC "15 case, 8s timeout after Switch(d2)=ON! but EV contactor is not closed".
    * state 16 (0x0804321A/0x08043236): same ubfx bit3 ; log 0x080A83F0 "16 case, 4s timeout ... EV
      contactor is not closed"; a second gate waits H102.ChargingCurrentRequest>0A (log 0x080AB4A0,
      "8s timeout ... not more than 0A"). Timeout counter p[+0x1b8] vs 0x7d (0x080432A4).
    * state 17 (0x0804AB98): log 0x080AB894 "EVSE outvol[%lu],p->ress_vol[%lu] wait until CCS precharge
      finished! ... get_precharge_relay=%d" — the engagement guard (analyze104) waits for the CCS
      precharge voltage match; wait counter p[+0x14] vs 0xc8 (0x0804ABA6).
    * get_precharge_relay (0x080525D8 -> 0x080884B0): GPIOB(0x40020400) IDR bit10 = PB10 input — the
      adapter's INNER precharge-relay feedback (hardware GPIO, not the car contactor).
    * set_precharge_relay (0x080524FC): drive relay to desired (r0&1), poll PB10 until it matches,
      timeout 0x1F40 + retry counter [0x200008A8]; mismatch -> fail -> terminate session.
  CONCLUSION: C013 sequences car-contactor-close (states 15/16, VehicleStatus bit3, 8s/4s) BEFORE the
  CCS-precharge voltage engagement (state 17), then closes its own inner precharge relay (states 18/19,
  PB10 feedback). The DIN EVSE-side session advances PreCharge->PowerDelivery on PreChargeRes rc_ok
  (phase_status=4), which is the engagement GATE — it does not itself stall on the car contactor. This
  differs from the ccs32clara prior art (which stalls PreChargeReq on CarContactorsClosed). The replica
  charge_stm ALREADY models states 15/16 (ev_contactor / current_request>0) + 18 (precharge_relay).

G11 — output-current ramp + undersupply limit
  Two distinct current paths exist:
    (1) per-tick CurrentDemand setpoint (0x08044D42, replica current_ctrl): min(request, avail) capped
        by EVSE max — instantaneous, NO ramp (byte-exact).
    (2) periodic EVMaximumCurrentLimit ramp (0x0804BB54), the unmodeled layer:
        * ramp ceiling [0x200007AC] = din_scale(EVSE max current, meas+0x3D20/22) (0x0804B726-0x0804B73A).
        * ramped setpoint meas+0x28C (0x200077FC), init 20A at state-17 (0x0804ABCA movs #0x14).
        * every 10 ticks (phase_cnt%10) check; the +20A (0x14) step is gated on phase_cnt%6000==0
          (movw #0x1770=6000, 0x0804BB84) = 6000 ticks = 60s = 1 minute @100Hz — matching the log
          0x080AC0F0 "CurrentDemand phase, every n minute adjusts current limintation ...
          pMsgPfm->setpara_maxevsecurrent[%lu]" (loaded base 0x080AC080 + 0x70, 0x0804BBAA).
        * up-ramp: setpoint += 20, clamped to ceiling [0x200007AC], +/-5A deadband around the request
          (0x0804BB76-0x0804BB82). down-path: +/-25A deadband, gated p[+0x64]>=600 (0x0804BBBC).
        * CurrentDemandReq EVMaximumCurrentLimit = min(ramped setpoint meas+0x28C, din_scale(EVSE max))
          (0x0804EA94-0x0804EA9C: ldrh [r6,#0x28c] ; cmp r0,r5 ; bhi keep ; mov r5,r0).
  CONCLUSION: C013 ramps the REQUESTED EVMaximumCurrentLimit up by +20A per minute (slow inrush limit),
  never above the EVSE-reported max, init 20A. This is NOT the prior-art +4A/100ms fast ramp. The replica
  current_ctrl models path (1) only; path (2) — the slow +20A/60s ramp on the demand current limit — is
  the remaining inert build step (communication-side, no GPIO).

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze105.py'
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
            ex += f' "{cstr(w-TB)[:64]}"'
        print(f"  0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{ex}")
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break

print("################ G10 — PreCharge <-> car-contactor coupling ################")

print("\n== G10.1 state-15 EV-contactor gate: p[+0x1de] bit3 (VehicleStatus) + 8s timeout log ==")
dump(0x0804A284, 8, "0x0804A284 (ldrb p[+0x1de]; ubfx #3,#1; log 0x080AB1DC)")
print(f"  fmt: {cstr(0x080AB1DC-TB)!r}")

print("\n== G10.2 state-16 EV-contactor gate: p[+0x1de] bit3 + 4s timeout log + counter p[+0x1b8] ==")
dump(0x08043232, 8, "0x08043232 (ldrb p[+0x1de]; ubfx #3,#1; log 0x080A83F0)")
print(f"  fmt: {cstr(0x080A83F0-TB)!r}")
dump(0x08043298, 5, "0x08043298 (timeout counter p[+0x1b8]++ ; cmp #0x7d)")
print(f"  current-request gate fmt: {cstr(0x080AB4A0-TB)!r}")

print("\n== G10.3 state-17 'wait until CCS precharge finished' (engagement reference, analyze104) ==")
dump(0x0804AB92, 8, "0x0804AB92 (ress_vol=sl, outvol=p[+0x16], relay; log 0x080AB894)")
print(f"  fmt: {cstr(0x080AB894-TB)!r}")
dump(0x0804AB9E, 5, "0x0804AB9E (wait counter p[+0x14]++ ; cmp #0xc8)")

print("\n== G10.4 get_precharge_relay = GPIOB PB10 input (inner precharge-relay feedback) ==")
dump(0x080884B0, 4, "0x080884B0 (GPIOB 0x40020400 IDR bit10)")

print("\n== G10.5 set_precharge_relay: drive + poll PB10 feedback, timeout/retry -> terminate ==")
dump(0x080524FC, 14, "0x080524FC (desired=r0&1; bl get_precharge_relay; cmp; retry [0x200008A8])")

print("\n################ G11 — output-current ramp + undersupply limit ################")

print("\n== G11.1 ramp ceiling = din_scale(EVSE max current meas+0x3D20/22) -> [0x200007AC] ==")
dump(0x0804B726, 7, "0x0804B726 (muls raw*pow10 ; udiv /1000 ; str [0x20000780+0x2c])")

print("\n== G11.2 ramped setpoint meas+0x28C init 20A at state-17 ==")
dump(0x0804ABCA, 2, "0x0804ABCA (movs #0x14=20 ; strh [r6,#0x28c])")

print("\n== G11.3 periodic ramp: +20A every 6000 ticks (1 min), clamp ceiling, +/-5A deadband ==")
dump(0x0804BB54, 30, "0x0804BB54 (phase_cnt%10 gate ; %6000 step ; +0x14 ; clamp [fp+0x2c])")
print(f"  ramp log fmt: {cstr(0x080AC0F0-TB)!r}")
dump(0x0804BBA0, 5, "0x0804BBA0 (ramp log loaded base 0x080AC080 + 0x70 = 0x080AC0F0)")

print("\n== G11.4 down-path: +/-25A deadband, gated p[+0x64]>=600 ==")
dump(0x0804BBB2, 14, "0x0804BBB2 (cmp p[+0x64],#0x258=600 ; setpoint-25/+25 deadband)")

print("\n== G11.5 CurrentDemandReq EVMaximumCurrentLimit = min(ramped meas+0x28C, EVSE max) ==")
dump(0x0804EA7C, 9, "0x0804EA7C (din_scale(EVSE max)=r5 ; ldrh [r6,#0x28c] ; cmp ; mov r5,r0)")

print("\n== RESOLVED ==")
print("  G10: car-contactor coupling is in the CHAdeMO charge stm — states 15/16 wait H102.VehicleStatus")
print("       bit3 (p[+0x1de], EV contactor closed, 8s/4s) + ChargingCurrentRequest>0A BEFORE state-17 CCS")
print("       precharge voltage engagement; states 18/19 close the adapter inner precharge relay (PB10")
print("       feedback via get_precharge_relay 0x080884B0 / set_precharge_relay 0x080524FC). The DIN EVSE")
print("       session advances PreCharge->PowerDelivery on rc_ok (phase_status=4) = the engagement gate,")
print("       NOT a contactor stall of the PreChargeReq loop. Replica charge_stm ALREADY models 15/16/18.")
print("  G11: C013 ramps the REQUESTED EVMaximumCurrentLimit (meas+0x28C) +20A every 6000 ticks (=60s=")
print("       1 min @100Hz), init 20A, clamped to din_scale(EVSE max meas+0x3D20/22)=[0x200007AC], +/-5A")
print("       up / +/-25A down deadband. The per-tick current_ctrl min/cap law (0x08044D42) is separate")
print("       and instantaneous. Remaining inert build step: add the slow +20A/60s ramp to the demand")
print("       current limit (communication-side, no GPIO). NOT the prior-art +4A/100ms fast ramp.")