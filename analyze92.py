#!/usr/bin/env python3
"""analyze92.py — CCS2 EVCC upper layers (SLAC + CP/PP + SDP/V2GTP + DIN70121), byte-exact (REPORT §5.9).

Re-derives from the C013 firmware bytes the CCS2 EVSE-side subsystem that sits ABOVE the QCA7005
PLC transport (analyze91) and supplies the CHAdeMO charge state machine's EVSE handshake inputs +
the output-current control's EVSE measurements + the CurrentDemandReq actuation. Replicated INERT
in custom_fw/src/{slac,cp,sdp,v2gtp,din70121,ccs2}.c (host-tested test_{slac,cp,sdp,v2gtp,din70121,
ccs2}.c). The autonomous EXI bit-grammar + distributed session timers/retries + live UDP/TCP/IPv6 +
mbedTLS transport are NOT recovered (gated); the confirmed measurement + actuation field maps are.

LOAD-BEARING CORRECTION (analyze89): the PhysicalValueType converter 0x0804E786 is a POWER-OF-10
TABLE lookup, NOT "(code<7)?code:0xFF". It returns pow10[code] for code in [0,6] (table @RAM
0x20000808, populated at init = {1,10,100,1000,10000,100000,1000000}), else 0xFF (255). The sxtb
is in the CALLER (state-30 0x08044D4C), not the converter. scale(raw,factor)=(u16)(raw*pow10[factor]
/1000); real value = raw*10^(factor-3); the stored factor byte = wire multiplier + 3. The DIN helper
0x0802B92C indexes the same pow10 table (@RAM 0x20000400) by signed mult in [-3,3] (else 0xFFFF).
This corrects the committed current_ctrl converter (now delegates to din_pow10/din_scale).

Resolved layers (anchors below):
  SLAC  ISO15118-3 matching: top SM 0x08021FCE (ctx 0x20002AC4, state 0..33), subprocess 0x0802166E
        (ctx[0x1c]); MME seq PARM.REQ 0x6064->CNF 0x6065->START_ATTEN 0x606A->ATTEN 0x606E->RSP
        0x606F->MNBC_SOUND 0x6076 x10->MATCH.REQ 0x607C->CNF 0x607D->SET_KEY 0x6008->CNF 0x6009.
        MATCH.CNF handler 0x08021AE4 (NID@+0x55[7], NMK@+0x5D[16]); PRNG LCG 0x08022C9C
        (n=9*seed+7 &0xFFFF twice). Outputs NID@0x20002AA1, NMK@0x20002AA9, link@0x20002AB9.
  CP/PP AD_PP 0x08088850 (raw*3300/65520 mV), AD_CPD 0x08088878 (raw*3300/32760), CP analog
        0x08088864 (raw*6600/32760); CP_ST 0x08052914 (duty0->'E', PD11!=0->'C', else 'B');
        duty-5 0x08052804 ([30,70]->'5'); PP plug 0x080527B0 (<=2146mV x4 plugged / >=2296 x4
        unplugged, hysteresis+4-debounce, binary presence); D_LINK 0x080884BA (PB12).
  SDP   SM 0x08020468 (ctx 0x20000BBC); security select 0x080204FA (req 0x10 TLS iff
        (RootCertCount&0xFF)==0 else 0x00, LOW-BYTE-ONLY); cert-count accessor 0x08051AAC
        (base 0x20018A6C-0x28, ldrb[+0x24]<<24 | ldr[+0x20]); res validator 0x080212E0 (type
        0x9001, len 28, transport 0, security in {0,0x10}, IP!=0, port!=0); V2GTP parser
        0x080212C2 ([0]=01,[1]=FE,type BE,len BE); appHandshake 0x08033B4E (DIN urn:din:70121:2012
        Priority1/SchemaID1, ISO urn:iso:15118:2:2013 Priority2/SchemaID2); set-protocol 0x08023A8C
        (selected@0x200137CC, 1=DIN/2=ISO). SDP req 01 FE 90 00 00 00 00 02 <SEC> 00; res 28 B
        (SECC IPv6@+8, port BE@+0x18, security@+0x1a, transport@+0x1b). TLS iff SECC security!=0.
  DIN   meas BASE 0x20007570 (EVCC handler 0x080353B2), evcc_sta=meas-0x90=0x200074E0,
        precharge_flag=evcc_sta+0x23F=0x2000771F. Map: +0x3D08/0A EVSEMaxVoltage, +0x3D14/16
        EVSEPresentCurrent, +0x3D18/1A EVSEPresentVoltage, +0x3D20/22 EVSEMaxCurrent, +0x3D1B/1C/1D
        Current/Voltage/PowerLimitAchieved. CurrentDemandRes decoder 0x0802DC0A (EXI presentV
        [0x0E]/[0x0C], presentI [0x12]/[0x10], maxV [0x22]/[0x20] present[0x24]bit0, maxI
        [0x28]/[0x26] present[0x2A]bit0, achieved [0x14]/[0x1C]/[0x18]; stored factor=wire+3;
        optional-absent keeps previous). EV targets meas[0x3CE0]/[0x3CE2]/[0x3CE4/CE5] factors;
        parameter-setter 0x0802B768 arm 0x606 (0x0802B8F6): command{+4 cur u16,+6 volt u16,+8
        packed factors bits0-2 cur/bits3-5 volt}. CurrentDemandReq encoder 0x0802C2CE (excerpt
        0x0802C406): meas[0x3CE0]->EXI[0x18]/[0x3CE4]-3->EXI[0x14], meas[0x3CE2]->EXI[0x68]/
        [0x3CE5]-3->EXI[0x64], DC_EVStatus meas[0x3CB7]->EXI[0x40]/[0x3CB8]->EXI[0x48]/EXI[0x44]=1,
        first_demand_sent meas[0x243]; TX buf 0x20013698 len 108. Isolation struct 0x20000868
        {+0 valid,+1 level,+2 mode} getter 0x0805206C. CPD Res writer 0x0802BEC0.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze92.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f): return TB + f
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

def dump(addr, n, label, stop=True):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = ""
        if w is not None:
            tag = (" FLASH" if 0x08000000 <= w < 0x08100000 else
                   " RAM" if 0x20000000 <= w < 0x20030000 else
                   " PERIPH" if 0x40000000 <= w < 0x40100000 else "")
            ex = f"  ; =0x{w:08X}{tag}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:9s} {i.op_str}{ex}")
        a += i.size
        if stop and i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if stop and i.mnemonic == 'pop' and 'pc' in i.op_str: break

print("################ CCS2 EVCC UPPER LAYERS (§5.9, byte-exact, C013) ################")

print("\n#### LOAD-BEARING CORRECTION: PhysicalValueType converter (analyze89 mis-decode) ####")
dump(0x0804E786, 16, "converter 0x0804E786 = pow10 TABLE[code] (code<7) else 0xFF — NOT identity")
print("  resolved: cmp r0,#7; blt -> ldr r0,[0x20000808 + code*4] (pow10 table); else movs r0,#0xff.")
print("  pow10 table (RAM 0x20000808, init-populated) = {1,10,100,1000,10000,100000,1000000}.")
print("  scale(raw,factor)=(u16)(raw*pow10[factor]/1000); real=raw*10^(factor-3); stored=wire+3.")
dump(0x0802B92C, 24, "DIN pow10 helper 0x0802B92C (signed mult [-3,3] -> table@0x20000400, else 0xFFFF)")

print("\n#### DIN70121 measurement + CurrentDemand actuation ####")
dump(0x0802DC0A, 60, "CurrentDemandRes decoder 0x0802DC0A (EXI field map -> meas, factor=wire+3)", stop=False)
dump(0x0802C406, 48, "CurrentDemandReq encoder excerpt 0x0802C406 (meas EV targets -> EXI, wire=stored-3)", stop=False)
dump(0x0802B8F6, 32, "parameter-setter arm 0x606 (0x0802B8F6): command -> meas[0x3CE0/2/4/5]", stop=False)
dump(0x0805206C, 18, "isolation getter 0x0805206C (struct 0x20000868 {valid,level,mode})")

print("\n#### SLAC ISO15118-3 matching ####")
dump(0x08022C9C, 22, "SLAC PRNG LCG 0x08022C9C (n=9*seed+7 &0xFFFF twice, ret hi<<16|lo)")
dump(0x08021AE4, 40, "MATCH.CNF handler 0x08021AE4 (NID@+0x55[7], NMK@+0x5D[16], adds r5,#9)", stop=False)

print("\n#### SDP / V2GTP / appHandshake ####")
dump(0x080204FA, 22, "SDP security select 0x080204FA (req 0x10 TLS iff (count&0xFF)==0, LOW-BYTE tst)")
dump(0x08051AAC, 22, "Root-cert-count accessor 0x08051AAC (base 0x20018A6C-0x28, bfi #24,#8)")
dump(0x080212E0, 40, "SDP response validator 0x080212E0 (type 0x9001, len 28, transport 0, sec {0,0x10})", stop=False)
dump(0x080212C2, 24, "V2GTP parser 0x080212C2 ([0]=01,[1]=FE,type BE,len BE; returns byte-swapped type)")

print("\n#### CP / PP analog signaling ####")
dump(0x08088850, 16, "AD_PP 0x08088850 (raw*3300/65520 mV)")
dump(0x080527B0, 40, "PP plug-in 0x080527B0 (<=2146mV x4 plugged / >=2296 x4 unplugged, debounce)", stop=False)
dump(0x08052914, 28, "CP_ST 0x08052914 (duty0->'E', PD11!=0->'C', else 'B'; fault fn stubbed)")

print("\n== RESOLVED CCS2 EVCC subsystem (C013) ==")
print("  Stack: qca7005 (SPI1 transport, analyze91) -> slac (matching) -> cp (CP/PP) -> sdp/v2gtp")
print("         (discovery) -> din70121 (measurement+actuation) -> ccs2 (EVCC controller glue).")
print("  meas BASE 0x20007570; evcc_sta 0x200074E0; precharge_flag 0x2000771F (evcc_sta+0x23F).")
print("  EVSE meas: maxV +0x3D08/0A, presentI +0x3D14/16, presentV +0x3D18/1A, maxI +0x3D20/22,")
print("             achieved +0x3D1B/1C/1D. EV targets +0x3CE0/2/4/5. CDReq TX buf 0x20013698 len108.")
print("  Integration: ccs2_evse() -> charge_stm EVSE inputs (isolation/precharge_flag/plug_in/...);")
print("               ccs2_fill_current_ctrl() -> current_ctrl EVSE meas (max/avail current+factors,")
print("               voltage limit); ccs2_demand(setpoint) -> din_cd_req_encode -> CurrentDemandReq EXI.")
print("  Actuation architecture (§5.21 F): NO local PWM/DAC — the setpoint is commanded upstream as a")
print("               CCS2 CurrentDemandReq PLC message (EVSE regulates); contactor GPIO switches power.")
print("  GATED (not recovered): full DIN EXI bit-grammar, distributed session timers/retries +")
print("               FAILED->shutdown, live UDP/TCP/IPv6 + mbedTLS transport, exact EVSEIsolationStatus")
print("               ->level 3/4 mapping, CP/PP analog front-end acquisition (TIM4 CP capture anchors).")
print("  Replicated INERT in custom_fw/src/{slac,cp,sdp,v2gtp,din70121,ccs2}.c; communication only, NO")
print("  power GPIO. Host-tested (307 checks total); built-image power-GPIO safety + pow10 table")
print("  disasm-verified (custom_fw/verify_ccs2.py). Converter correction applied to current_ctrl.")