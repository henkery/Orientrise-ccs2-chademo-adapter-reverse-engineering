#!/usr/bin/env python3
"""analyze93.py — DIN70121 EXI bit-grammar codec + distributed session state machine (REPORT §5.9).

Re-derives from the C013 firmware bytes the two GATED layers that sit ABOVE the DIN70121
measurement/actuation field maps (analyze92): (E) the full EXI bit-level grammar/codec, and (F) the
distributed session state-machine timers/retries + FAILED->shutdown. Replicated INERT in
custom_fw/src/{exi,din70121,din_session}.c (host-tested test_{exi,din_session,din70121,ccs2}.c).
The live UDP/TCP/IPv6 + mbedTLS transport that feeds decoded Res frames stays GATED (not recovered).

(E) EXI CODEC — generated grammar-table-driven OpenV2G (Siemens) style processor. A merged
DIN+ISO+XMLDSIG root reads a 7-bit event and tbb-dispatches to 81 productions; each production is a
while-loop switch(grammar_id) with state 4 = EE. Bit order is MSB-first.
  readBits core 0x0809DA5E (fetch 0x0809DA34): single-byte (curbyte>>(bitsleft-n))&(0xFF>>(8-n));
    multi-byte *out<<8|newbyte; fetch curbyte=buf[pos++] when bitsleft==0, EOF if pos>=cap.
  writeBits core 0x0809DAE2: curbyte=(curbyte<<n)|(val&mask_n), bitsleft-=n, flush buf[pos++]=curbyte
    when bitsleft==0; init curbyte=0/bitsleft=8; capacity checked ONLY on flush; the partial trailing
    byte is left-aligned (curbyte<<bitsleft) at finish. Stream struct {+0 cap,+4 buf,+8 &pos,+0xC
    curbyte,+0xD bitsleft}.
  Primitives: bool 0x080934BE (1-bit, calls core), u16 varlen 0x08093404 (7-bit groups LSB-first,
    bit7 continuation via lsrs#7), u32 0x08093432, signed 0x080934F0 (sign-bit via bool + u16 magnitude
    + mvns ones-complement), octet 0x080935D8.
  PhysicalValueType decoder 0x08062070 wire order Multiplier(3-bit, wire=mult+3, subs#3->signed),
    Unit(2-bit choice; if 0: 4-bit + bit16 orr#0x10000 present), Value(signed) — NOT schema order.
    Encoder 0x0806A3AC.
  Framing [8B V2GTP][0x80 leading][7-bit root event][body], payload 0x8001. Decode wrapper 0x08033C24
    (cap 0x100, scratch 0x200031D0, strip 8). Root decoder 0x0806997A (pre-check 0x08093C66 + doc init
    0x08061BDE + readBits7 + cmp#0x51 + tbb 0x080699BC). Encoder root 0x0806FA9C. TX leading-0x80
    0x08093C92; RX pre-check rejects 0x24 + bit5 test (lsls#0x1a bpl). EXI errors: -11 EOF, -108
    unknown event, -110 empty, -137/-138 header.

  LOAD-BEARING EV-MAP CORRECTION: the agent-E event numbering is +2-shifted for ev>=0x0e (the b-thunk
  region). Ground truth (this script follows the ACTUAL tbb byte -> stub -> b-thunk -> bl decoder +
  orr flag): CurrentDemandRes 0x0806471E/flag 4148.7 = ev0x12; DC_EVSEStatus 0x0806259E/4140.26 =
  ev0x16; DC_EVSEChargeParam 0x080650D2/4144.5 = ev0x15; CPD wrapper 0x080650AC = ev0x1d; SessionStop
  0x08063C04/4144.6 = ev0x1e; CableCheckRes 0x08066C5C/4144.24 = ev0x05; PreCharge/Welding
  0x08063A8A/4148.8 = ev0x30, 0x08062754/4144.30 = ev0x4f; ev0-type 0x08065FFC = ev0x00. The decoder
  ADDRESSES + flag bits + field lists E recovered are correct; only the event NUMBERS were shifted.

(F) SESSION SM — distributed: RX handler 0x080353B2 = transition engine (advances only on a valid
Res); poll task 0x08038192 = timer/retry/re-send engine (never advances on success); RTOS loop
0x08039AF8 (~10 ms). State variable = session ctx 0x2000B3B0[0] (byte enum 0..13 = "which Res is
awaited"), first field of a 0x48-byte ctx (= 0x2000B3F8 - 0x48); dispatch tbh 0x08035444 (gate
cmp#0xe). TIM7 (0x40001400) ISR 0x0808A198 -> [0x20000A54] u32++, init 0x0808A1AA PSC=83/ARR=999 ->
1 ms tick, accessor 0x0808A236.
  Init 0x08035198 timers: ctx+4 u16=4000 (resp-wait, re-armed every send), +8 u32=120000, +C u32=
    150000, +10 u16=40000, +12 u16=14000. The 120s/150s are session-GLOBAL (f_24 compare
    0x08038458/0x0803874E, gate ctx+0x2A); the 40s/14s are engagement/charging-PHASE (f_27 compare
    0x08039002/0x0803940E, clustered with the CD cadence) — they must NOT preempt the early-handshake
    resp-wait/retry loop.
  Retry cap 20: meas[0x244]++ (uxtb wrap) cmp#0x14 @0x0803829C -> bls skip; else meas[0x248]=1 +
    fault code 1. CD cadence PRIMARY meas[0xC]%fp==0 (udiv/mls @0x080396F6); fp getter
    0x08088B6C=ldrh[0x200009FE] runtime-negotiated via config-registry 0x08088B9E (table 0x200226E0).
    SECONDARY ctx+0x44 interval / ctx+0x46 arm gated @0x08039698 (parameterized; set-site [?]).
  Fault setter 0x0802C9D0(code) -> 0x20000774[1]=code,[2]=1,[0]=code; CHAdeMO reads it to open the
    contactor. Codes 1,2,7,9,11,14,16,40,42,46(0x2e). FAILED -> SessionStopReq 0x08034F72 + state13;
    timeout -> fault -> PowerDelivery-stop 0x08034A78 -> SessionStop -> state13 -> reset 0x08035318.
  Sequence 2->3(RC==0)->6(DIN skips 4/5 [?])->7->8(isolation==1)->9->10(loop)->11->12->13->0.
    CableCheckRes isolation: ==1 Valid->advance 0x080366AE, ==0->retry, >=2->fault16. PreChargeRes
    decoder 0x0802C27A -> meas[0x3D18] presentV / [0x3D1A] factor+3 / [0x3D1E]=4.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze93.py'
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

def stub_info(addr):
    """follow b-thunks; in the direct stub find first bl (decoder) + the orr flag (word,bit)."""
    a = addr; dec = None; flag = None; seq = []
    for _ in range(14):
        ins = list(md.disasm(fw[a-TB:a-TB+8], a, count=1))
        if not ins: break
        i = ins[0]; mn = i.mnemonic.split('.')[0]; ops = i.operands
        if mn == 'b' and ops and ops[0].type == 2 and dec is None:
            a = ops[0].imm & 0xFFFFFFFF; continue
        seq.append(i)
        if mn == 'bl' and ops and ops[0].type == 2 and dec is None:
            dec = ops[0].imm & 0xFFFFFFFF
        if mn == 'orr' and len(ops) >= 3 and ops[2].type == 2 and dec is not None and flag is None:
            bit = ops[2].imm & 0xFFFFFFFF
            if bit: flag = (bit.bit_length()-1)
        if mn == 'b' and dec is not None: break
        a += i.size
    word = None
    for i in seq:
        if i.mnemonic.split('.')[0] == 'ldr' and len(i.operands) >= 2 and i.operands[1].type == 3:
            d = i.operands[1].mem.disp
            if d in (0x140, 0x144, 0x148): word = 0x4140 + (d-0x140)
    return dec, word, flag

print("################ DIN70121 EXI GRAMMAR + SESSION SM (§5.9, byte-exact, C013) ################")

print("\n#### (E) EXI bit-level primitive codec ####")
dump(0x0809DA34, 12, "readBits fetch 0x0809DA34 (curbyte=buf[pos++] when bitsleft==0, EOF pos>=cap)")
dump(0x0809DA5E, 26, "readBits core 0x0809DA5E (MSB-first: (curbyte>>(bitsleft-n))&(0xFF>>(8-n)))")
dump(0x0809DAE2, 26, "writeBits core 0x0809DAE2 (curbyte=(curbyte<<n)|(val&mask); flush when bitsleft==0)")
dump(0x08093404, 22, "u16 varlen 0x08093404 (7-bit groups LSB-first, bit7 continuation lsrs#7)")
dump(0x080934F0, 24, "signed 0x080934F0 (sign-bit via bool + u16 magnitude + mvns ones-complement)")
dump(0x080934BE, 12, "bool 0x080934BE (1-bit, calls readBits core 0x0809DA5E)")

print("\n#### (E) PhysicalValueType wire order (Multiplier,Unit,Value — NOT schema order) ####")
dump(0x08062070, 60, "PVT decoder 0x08062070 (3-bit mult subs#3, 2-bit unit choice + 4-bit, signed value)", stop=False)

print("\n#### (E) EXI framing + root dispatch ####")
dump(0x08093C66, 18, "RX pre-check 0x08093C66 (rejects leading 0x24 + bit5 test lsls#0x1a bpl)")
dump(0x08093C92, 12, "TX leading-0x80 0x08093C92")
dump(0x0806997A, 26, "root decoder 0x0806997A (readBits7 + cmp#0x51 + tbb 0x080699BC, 81 productions)")
dump(0x08033C24, 24, "decode wrapper 0x08033C24 (cap 0x100, scratch 0x200031D0, strip 8-byte V2GTP)")

print("\n#### (E) key DIN DC grammar productions ####")
dump(0x0806471E, 40, "CurrentDemandRes 0x0806471E (ev0x12, 10 fields)", stop=False)
dump(0x0806259E, 30, "DC_EVSEStatus 0x0806259E (ev0x16: isolation opt 2-bit, notification 2-bit, code 4-bit)", stop=False)
dump(0x08066C5C, 24, "CableCheckRes 0x08066C5C (ev0x05: RC + DC_EVSEStatus + processing 1-bit)", stop=False)
dump(0x08063C04, 14, "SessionStopRes 0x08063C04 (ev0x1e: EMPTY, 1-bit choice 0=OK/1=err-110)")

print("\n#### (E) LOAD-BEARING EV-MAP CORRECTION — ground-truth tbb walk (E was +2-shifted ev>=0x0e) ####")
t = 0x080699BC - TB
table = [fw[t+k] for k in range(81)]
key = {0x00: "ev0-type", 0x05: "CableCheckRes", 0x12: "CurrentDemandRes", 0x15: "DC_EVSEChargeParam",
       0x16: "DC_EVSEStatus", 0x1d: "CPD wrapper", 0x1e: "SessionStop", 0x30: "PreChargeRes",
       0x4f: "WeldingDetectionRes"}
print("  ev  stub        decoder     flagword.bit  name")
for ev in sorted(key):
    s = 0x080699BC + 2*table[ev]
    dec, word, bit = stub_info(s)
    fl = f"{word:x}.{bit}" if (word and bit is not None) else "-"
    print(f"  {ev:02x}  {s:08X}  {dec and hex(dec) or 'None':10s}  {fl:12s}  {key[ev]}")
print("  resolved: decoder addresses + flag bits + field lists are correct; only E's event NUMBERS")
print("  were +2-shifted in the b-thunk region (ev>=0x0e). tbb base 0x080699BC (instr 0x080699B8+4).")

print("\n#### (F) distributed session state machine ####")
dump(0x08035198, 30, "session ctx init 0x08035198 (timers +4=4000,+8=120000,+C=150000,+10=40000,+12=14000)", stop=False)
dump(0x0808A198, 12, "TIM7 ISR 0x0808A198 ([0x20000A54] u32++ ; 1 ms tick)")
dump(0x0808A236, 8, "tick accessor 0x0808A236 (ldr [0x20000A54])")
dump(0x080353B2, 30, "RX transition engine 0x080353B2 (meas base 0x20007570; advances on valid Res)", stop=False)
dump(0x08038298, 12, "retry cap 0x08038298 (meas[0x244]++ cmp#0x14 @0x0803829C -> fault code 1)")
dump(0x080396F6, 12, "CD modulo cadence 0x080396F6 (meas[0xC] % fp == 0 -> re-send CurrentDemandReq)")
dump(0x08039698, 12, "CD secondary interval 0x08039698 (ctx+0x44 vs ctx+0x40, gated ctx+0x46==1)")
dump(0x0802C9D0, 18, "fault setter 0x0802C9D0(code) -> 0x20000774[1]=code,[2]=1,[0]=code")
dump(0x080366AE, 16, "CableCheck isolation==1 Valid -> advance 0x080366AE (7->8)")
dump(0x08035318, 16, "session reset 0x08035318 (clears 0x48-byte ctx; state 13 -> 0)")

print("\n== RESOLVED EXI grammar + session SM (C013) ==")
print("  (E) EXI codec: generated grammar-table-driven OpenV2G-style; MSB-first bit primitives")
print("      (readBits 0x0809DA5E / writeBits 0x0809DAE2), varlen u16/u32, signed ones-complement,")
print("      octet, PVT wire order (Multiplier,Unit,Value). Root 7-bit event -> tbb 81 productions.")
print("      Framing [8B V2GTP][0x80][7-bit ev][body]; RX pre-check rejects 0x24 + bit5. Errors")
print("      -11 EOF / -108 event / -110 empty / -137 header. EV-MAP CORRECTED (E +2-shift ev>=0x0e).")
print("  (F) Session SM: state ctx 0x2000B3B0[0] enum 0..13; RX engine 0x080353B2 + poll engine")
print("      0x08038192 off TIM7 1 ms tick. Timers 4000(resp-wait)/120000/150000(global)/40000/14000")
print("      (phase); retry cap 20 -> fault 1; CD modulo cadence fp (runtime-negotiated); FAILED ->")
print("      SessionStop + fault post 0x0802C9D0 -> 0x20000774 (CHAdeMO opens contactor). Sequence")
print("      2->3->6->7->8(iso==1)->9->10(loop)->11->12->13->0; CableCheck iso>=2 -> fault 16.")
print("  Replicated INERT in custom_fw/src/{exi,din70121,din_session}.c + wired into ccs2.c/main.c;")
print("      communication only, NO power GPIO. Host-tested (test_exi 55, test_din_session 39,")
print("      test_din70121 36, test_ccs2 21); built-image power-GPIO safety + timer constants")
print("      disasm-verified (custom_fw/verify_ccs2.py). Power-stage drive stays GATED.")
print("  GATED (not recovered): live UDP/TCP/IPv6 + mbedTLS transport (feeds ccs2_rx_exi), exact")
print("      Req-side EXI grammars / root-event numbering [?], DIN-vs-ISO DC_EVSEStatus layout [?],")
print("      CD secondary interval set-site [?], exact EVSEIsolationStatus->level 3/4 mapping.")