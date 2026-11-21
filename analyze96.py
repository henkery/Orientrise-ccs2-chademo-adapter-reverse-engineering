#!/usr/bin/env python3
"""analyze96.py — IPv6 ND6 neighbor discovery + PnC CA cert store (REPORT §5.9, Agent N).

Re-derives from the C013 firmware bytes the two GATED third-party layers beneath the V2G network
transport (v2g_net.c, analyze94) that the custom_fw now replicates INERT (communication only — NO
power-stage GPIO). These are 2 of the 4 "lwIP/mbedTLS/ND6/CA hooks" recovered:

  (N-ND6) IPv6 Neighbor Discovery neighbor cache + NS/NA/RA.        [src/nd6.c]
  (N-CA)  Plug-and-Charge CA cert store (ext-SPI -> RAM ptr-array).  [src/ca_store.c]

The remaining two hooks (lwIP TCP reliability + mbedTLS crypto/TLS) are separate subsystems.

=============================================================================================
(N-ND6) IPv6 Neighbor Discovery (VERIFIED byte-exact; replicated in src/nd6.c, host-tested
        test_nd6.c 81 checks; disasm-verified verify_ccs2.py).
=============================================================================================
  RX chain    ethernet_input 0x0809D914 -> ip6_input 0x0809B88E / demux 0x0809BB2C (next-header
    6 TCP / 17 UDP / 58 ICMPv6 / 59 drop) -> icmp6_input 0x0809B3D0 -> nd6_input 0x0809C926.
  nd6_input   0x0809C926 entry: ldr r8 = ND6 global 0x20000B70 (pool @0x0809CB0C), ldr sb =
    neighbor cache 0x20024524 (pool @0x0809CB08), mov sl #4 (DELAY), mov fp #5 (counter). Type
    dispatch: cmp #0x87 (135 NS) @0x0809C948 / #0x86 (134 RA) @0x0809C952 / #0x88 (136 NA)
    @0x0809C958 / #0x89 (137 redirect) / #2 (PTB).
  cache       0x20024524 = 10 x 40B entries {+0 IPv6[16], +0x10 netif ptr, +0x14 MAC[6],
    +0x1C queue head, +0x20 state u8, +0x21 is_router u8, +0x24 counter u32}; entry = base+idx*40.
  ND6 global  0x20000B70 {+0 cached neighbor idx, +1 cached router idx, +4 reachable_time,
    +8 retransmit_time}.
  state enum  TBB @0x0809D030 jump bytes "37 03 0e 1c 1f 2b" -> 0 UNUSED / 1 INCOMPLETE /
    2 REACHABLE / 3 STALE / 4 DELAY / 5 PROBE.
  NA receive  0x0809C962: find_neighbor by TARGET addr; TLLA MAC copied ONLY if Override flag
    (byte4 bit5 = 0x20, lsls #0x1a / bpl); state = REACHABLE(2) movs r1,#2 @0x0809CAE2, store
    strb [r8,#0x20] @0x0809CAE6; counter = reachable_time store [r8,#0x24] @0x0809CAEE;
    flush_queue 0x0809C8BA.
  NS receive  neighbor by SRC; state = DELAY(4) strb sl,[r8,#0x20] @0x0809CC84 / counter = 5
    str fp,[r8,#0x24] @0x0809CC88 (DEVIATION from stock lwIP STALE=3 — C013 uses DELAY=5);
    SLLA MAC -> entry; if target == own -> NA reply (DAD src :: -> all-nodes ff02::1 flags 0x22;
    else solicited unicast flags 0x60).
  RA receive  reachable_time @RA+8 ntohl (only if non-zero) / retrans_timer @RA+12 ntohl -> ND6
    global; sender is_router = 1.
  nd6_send_ns 0x0809C520 wire: type135@0 / code0@1 / cksum@2-3 / reserved0@4-7 / target[16]@8-23 /
    SLLA {type1@24, len1@25, MAC[6]@26-31}; len byte = (hwaddr_len+9)>>3 = 1 (8-octet unit); pbuf
    alloc 0x18 + 1<<3 = 32; hop 255; flags bit0 -> solicited-node mcast ff02::1:ffXX:XXXX (scratch
    0x200248F4 word0=0x2ff / word1=0 / word2=0x1000000 / word3=target[3]|0xff); icmp6 cksum
    0x08098C72 proto 0x3a; output ip6_output_if 0x0809BC80.
  nd6_send_na 0x0809C7BA wire: type136@0 / code0 / cksum / flags byte4 = (flags & 0xF0)
    (R=0x80 / S=0x40 / O=0x20) / byte5-7=0 / target[16]@8 / TLLA {type2@24, len1@25, MAC[6]@26};
    dst flags bit0 -> solicited mcast / bit1 -> all-nodes ff02::1 / else unicast; hop 255.
  nd6_tmr     0x0809D012 (1 s): REACHABLE flush + counter -= 1000 -> STALE @<=1000 / counter 0;
    DELAY counter-- -> PROBE @<=1 / counter 0; INCOMPLETE/PROBE if counter>=3 && !is_router ->
    free else counter++ + send NS (INCOMPLETE mcast flags1 / PROBE unicast flags0); STALE counter++.
  TX lookup   ethip6_output 0x0809B35C -> 0x0809D5D6: mcast -> 33:33:dst[12..15]; STALE ->
    DELAY/counter5 + MAC; REACHABLE/DELAY/PROBE -> MAC; INCOMPLETE/UNUSED -> queue 0x0809D524 + NS.
  helpers     find_neighbor 0x0809C4AA / new_neighbor 0x0809C368 / free_neighbor 0x0809C32A /
    flush_queue 0x0809C8BA.
  [?]         pre-RA reachable/retransmit defaults (stock 30000/1000 unproven from bytes; the
    replica uses 30000/1000 and updates from RA).

=============================================================================================
(N-CA) Plug-and-Charge CA cert store (VERIFIED byte-exact; replicated in src/ca_store.c,
       host-tested test_ca_store.c 45 checks; disasm-verified verify_ccs2.py).
=============================================================================================
  TWO stores  (1) external SPI flash master: header @0x1F8000 (16B: [0] magic 0xCEA155E1,
    [4] version=1, [8] size, [12] byte-sum checksum), data @0x1F8010; read via SPI4 READ
    0x08088CFE (== custom_fw spi4_read). (2) internal A/B flash 0x0800C000 (sector3) /
    0x08010000 (sector4), memory-mapped (header [0] magic / [4] version=0 / [0x2638] seq /
    [0x263C] tail 0xCEA2AAE1).
  entry       808B (0x328) {+0 msg_code u32, +4 der_len u32 (<=800=0x320; Contract=0x20), +8 DER}.
  validators  0x08051CE2 (msg_code == expected && 0 < der_len <= 0x320), 0x08051CFE (Contract
    der_len == 0x20). Internal-store validator 0x08051500 (magic 0xCEA155E1 + tail 0xCEA2AAE1).
  slot map    internal offsets: Root 0x8101 slots0-4 @0x8/0x330/0x658/0x980/0xCA8; Pri_root
    0x8102 @0xFD0; Oem 0x8105 @0x12F8; 0x8104 @0x1620; 0x8103 @0x1948; Contract 0x8109 @0x1C70
    (40B); 0x8108 @0x1C98 / 0x8107 @0x1FC0 / 0x8106 @0x22E8; 0x8109 2nd @0x2610 (40B). Ext data
    = packed entry sequence (ext offset = internal offset - 8): Root i @808*i, Pri_root @808*5,
    Oem @808*6, Contract @808*9.
  refresh     0x0805184C: mov r0,#0x1F8000 (ext header), magic @0x08051862 / version==1 cmp
    @0x0805186C / size>=808 cmp #0x328 @0x08051872 / 4-aligned (lsls #0x1e) / byte-sum == hdr[12]
    @0x080518F8; cert-data start pool 0x001F8010; config base pool 0x20018A44.
  populate    0x080515CC: config 0x20018A44 memset 0x28; root loop validate(entry, 0x8101) ->
    0x08051680 r0 = entry+4 ({der_len, DER}) / 0x08051684 stm r6!,{r0} append compact NULL-term
    ptr-array @config+4 = 0x20018A48; count -> config[0x20] = 0x20018A64 (the SDP TLS gate).
  getter      0x08051ADC (pool 0x20018A6C - 0x24 -> 0x20018A48 ptr-array); caller 0x080208CA
    bl getter / movs r1,#0 @0x080208CE / bl mbedtls setup 0x080604D2 (loop <=5 ldm ptr / ldm
    der_len+DER / x509_crt_parse 0x0805D76C / ssl_conf_ca_chain 0x0808FAD6 / authmode arg1==0 ->
    2 VERIFY_REQUIRED movs r1,#2 @0x08060568 else 1 movs r1,#1 @0x08052E / ssl_conf_authmode
    0x0808F442). Dumper 0x0804F58E.
  *** CORRECTIONS to prior CA anchors ***: the earlier notes 0x08050E14 / 0x08050B94 /
    0x08051074 / 0x0804EB5C were GARBLED. The real cluster is 0x080515CC (populate) / 0x0805184C
    (refresh) / 0x08051500 (internal validator) / 0x0805159C (base getter, higher-seq) /
    0x08051526 (A/B commit) / 0x0804F58E (dumper) / 0x08051AAC. "flash -> RAM" = ext-SPI ->
    internal-A/B (memory-mapped) -> RAM ptr-array (NO bulk DER copy). The custom replica reads
    ext-SPI -> RAM directly (no internal A/B management). X509 DER parse = mbedTLS (Agent M).

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze96.py'
"""
import sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True

def u16(o): return int.from_bytes(fw[o:o+2], 'little')
def u32a(a):
    o = a - TB
    return int.from_bytes(fw[o:o+4], 'little') if 0 <= o <= N-4 else None
def rt(f): return TB + f
def dis(a, n):
    o = a - TB
    return list(md.disasm(fw[o:o+n*4], a))
def pool(ins):
    h = int.from_bytes(ins.bytes[:2], 'little')
    if (h & 0xF800) == 0x4800:
        p = ((ins.address + 4) & ~3) + (h & 0xFF)*4; return u32a(p)
    if (h & 0xFF7F) == 0xF85F and len(ins.bytes) >= 4:
        u = (h >> 7) & 1; im = int.from_bytes(ins.bytes[2:4], 'little') & 0xFFF
        p = ((ins.address + 4) & ~3) + (im if u else -im); return u32a(p)
    return None
def find(a, n, mn=None, imm=None):
    for ins in dis(a, n):
        if mn and ins.mnemonic.split('.')[0] != mn: continue
        if imm is not None:
            if not any(op.type == 2 and (op.imm & 0xFFFFFFFF) == (imm & 0xFFFFFFFF)
                       for op in ins.operands): continue
        return ins
    return None
def dump(addr, n, label, stop=True):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    for ins in dis(addr, n):
        w = pool(ins); ex = ""
        if w is not None:
            tag = (" FLASH" if 0x08000000 <= w < 0x08100000 else
                   " RAM" if 0x20000000 <= w < 0x20030000 else
                   " PERIPH" if 0x40000000 <= w < 0x40100000 else
                   " EXTFLASH" if 0x001F0000 <= w < 0x00200000 else "")
            ex = f"  ; =0x{w:08X}{tag}"
        print(f"  0x{ins.address:08X}: {ins.mnemonic:9s} {ins.op_str}{ex}")
        if stop and ins.mnemonic == 'bx' and 'lr' in ins.op_str: break
        if stop and ins.mnemonic == 'pop' and 'pc' in ins.op_str: break

checks = failures = 0
def check(cond, msg):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1; print("FAIL:", msg)

print("################ ND6 + PnC CA CERT STORE (§5.9, byte-exact, C013) ################")

# =============================================================================================
# (N-ND6) IPv6 Neighbor Discovery
# =============================================================================================
print("\n#### (ND6) nd6_input entry 0x0809C926 (global/cache pools + DELAY/counter consts) ####")
dump(0x0809C926, 14, "nd6_input entry 0x0809C926", stop=False)
i = find(0x0809C926, 12, 'mov', 4)
check(i is not None and i.address == 0x0809C93E, "mov sl,#4 @0x0809C93E (DELAY state const)")
i = find(0x0809C926, 14, 'mov', 5)
check(i is not None and i.address == 0x0809C942, "mov fp,#5 @0x0809C942 (NS-receive counter)")
pools = [pool(ins) for ins in dis(0x0809C926, 12)]
check(0x20000B70 in pools, "ND6 global pool 0x20000B70")
check(0x20024524 in pools, "neighbor cache pool 0x20024524 (10 x 40B)")

print("\n#### (ND6) ICMPv6 type dispatch (NS 135 / RA 134 / NA 136) ####")
check(find(0x0809C948, 1, 'cmp', 0x87) is not None, "cmp #0x87 (135 NS) @0x0809C948")
check(find(0x0809C952, 1, 'cmp', 0x86) is not None, "cmp #0x86 (134 RA) @0x0809C952")
check(find(0x0809C958, 1, 'cmp', 0x88) is not None, "cmp #0x88 (136 NA) @0x0809C958")

print("\n#### (ND6) NA-receive REACHABLE(2) + counter=reachable_time (0x0809CAE2..F0) ####")
dump(0x0809CAE0, 8, "NA-receive state/counter store", stop=False)
i = find(0x0809CAE0, 4, 'movs', 2)
check(i is not None and i.address == 0x0809CAE2, "movs r1,#2 @0x0809CAE2 (REACHABLE)")
ins = dis(0x0809CAE6, 1)[0]
check(ins.mnemonic.startswith('strb') and '#0x20]' in ins.op_str,
      "NA state=2 store strb [+0x20] @0x0809CAE6")
ins = dis(0x0809CAEE, 1)[0]
check(ins.mnemonic.startswith('str') and '#0x24]' in ins.op_str,
      "NA counter=reachable_time store [+0x24] @0x0809CAEE")

print("\n#### (ND6) NS-receive DELAY(4)/counter=5 DEVIATION (0x0809CC84/88) ####")
dump(0x0809CC84, 2, "NS-receive state/counter store", stop=False)
ins = dis(0x0809CC84, 1)[0]
check(ins.mnemonic.startswith('strb') and '[r8, #0x20]' in ins.op_str,
      "NS state=DELAY store strb sl,[r8,#0x20] @0x0809CC84 (deviation from stock STALE=3)")
ins = dis(0x0809CC88, 1)[0]
check(ins.mnemonic.startswith('str') and '[r8, #0x24]' in ins.op_str,
      "NS counter=5 store str fp,[r8,#0x24] @0x0809CC88")

print("\n#### (ND6) state enum TBB jump bytes @0x0809D030 (0..5) ####")
tb = fw[0x0809D030-TB:0x0809D030-TB+6]
print(f"  TBB bytes = {tb.hex()}")
check(tb == bytes([0x37, 0x03, 0x0e, 0x1c, 0x1f, 0x2b]),
      "TBB jump bytes 37 03 0e 1c 1f 2b (UNUSED/INCOMPLETE/REACHABLE/STALE/DELAY/PROBE)")

print("\n#### (ND6) wire builders nd6_send_ns 0x0809C520 / nd6_send_na 0x0809C7BA ####")
dump(0x0809C520, 24, "nd6_send_ns 0x0809C520 (type135 + SLLA)", stop=False)
dump(0x0809C7BA, 24, "nd6_send_na 0x0809C7BA (type136 + flags&0xF0 + TLLA)", stop=False)
dump(0x0809D012, 24, "nd6_tmr 0x0809D012 (1s state timer)", stop=False)

print("\n== RESOLVED IPv6 ND6 (C013, Agent N + byte-verification) ==")
print("  nd6_input 0x0809C926 dispatches ICMPv6 NS135/RA134/NA136 over a 10x40B neighbor cache")
print("  0x20024524 + ND6 global 0x20000B70. NA-receive -> REACHABLE(2)/counter=reachable_time")
print("  (0x0809CAE6/EE), TLLA MAC gated on Override(0x20). NS-receive -> DELAY(4)/counter=5")
print("  (0x0809CC84/88, a C013 DEVIATION from stock lwIP STALE=3). State enum TBB 0x0809D030.")
print("  Wire: NS type135+SLLA{1,1,MAC}/NA type136+flags&0xF0+TLLA{2,1,MAC}, hop255, solicited-node")
print("  mcast ff02::1:ffXX:XXXX. nd6_tmr 0x0809D012 1s countdown. Replicated INERT in src/nd6.c")
print("  (pure SM + wire logic, NO power GPIO; live TX behind a hook). host test_nd6 81 checks.")

# =============================================================================================
# (N-CA) Plug-and-Charge CA cert store
# =============================================================================================
print("\n#### (CA) internal-store validator 0x08051500 (magic + tail) ####")
dump(0x08051500, 30, "CA internal validator 0x08051500", stop=False)
pools = [pool(ins) for ins in dis(0x08051500, 40)]
check(0xCEA155E1 in pools, "validator magic pool 0xCEA155E1")
check(0xCEA2AAE1 in pools, "validator tail-magic pool 0xCEA2AAE1")

print("\n#### (CA) ext-flash refresh validation 0x0805184C (hdr@0x1F8000 / data@0x1F8010) ####")
dump(0x0805184C, 30, "CA ext refresh 0x0805184C", stop=False)
i = find(0x0805184C, 8, 'mov', 0x1f8000)
check(i is not None, "mov r0,#0x1F8000 (ext-flash header addr)")
pools = [pool(ins) for ins in dis(0x0805184C, 30)]
check(0xCEA155E1 in pools, "refresh magic pool 0xCEA155E1")
check(0x001F8010 in pools, "refresh cert-data start pool 0x001F8010")
check(0x20018A44 in pools, "refresh config base pool 0x20018A44")
check(find(0x0805186C, 1, 'cmp', 1) is not None, "ext header version==1 cmp @0x0805186C")
check(find(0x08051872, 1, 'cmp', 0x328) is not None, "ext header size>=808 cmp #0x328 @0x08051872")

print("\n#### (CA) root-cert-ptr array populate 0x08051680/84 (entry+4 / stm append) ####")
dump(0x08051680, 3, "CA populate ptr-array append", stop=False)
ins = dis(0x08051680, 1)[0]
check(ins.mnemonic.startswith('add') and '#4' in ins.op_str,
      "r0=entry+4 (ptr to {der_len,DER}) @0x08051680")
ins = dis(0x08051684, 1)[0]
check(ins.mnemonic.startswith('stm'), "stm r6!,{r0} compact ptr-array append @0x08051684")

print("\n#### (CA) cert-list getter 0x08051ADC + caller 0x080208CA -> mbedTLS setup ####")
dump(0x08051ADC, 4, "CA cert-list getter 0x08051ADC")
pools = [pool(ins) for ins in dis(0x08051ADC, 4)]
check(0x20018A6C in pools, "getter pool 0x20018A6C (-0x24 -> 0x20018A48 ptr-array)")
dump(0x080208CA, 6, "CA caller 0x080208CA (bl getter / movs r1,#0)", stop=False)
ins = dis(0x080208CE, 1)[0]
check(ins.mnemonic.startswith('movs') and '#0' in ins.op_str,
      "caller movs r1,#0 (arg1=0 -> authmode 2) @0x080208CE")

print("\n#### (CA) mbedTLS authmode mapping 0x08060528..34 / 0x08060568 (arg1==0 -> 2) ####")
dump(0x08060528, 4, "authmode arg1 test 0x08060528", stop=False)
ins = dis(0x08060528, 1)[0]
check(ins.mnemonic.startswith('cmp') and '#0' in ins.op_str, "cmp r8,#0 (arg1) @0x08060528")
ins = dis(0x0806052C, 1)[0]
check(ins.mnemonic.startswith('beq'), "beq -> authmode 2 branch @0x0806052C")
i = find(0x08060568, 3, 'movs', 2)
check(i is not None, "movs r1,#2 (VERIFY_REQUIRED) @0x08060568")
i = find(0x0806052E, 2, 'movs', 1)
check(i is not None, "movs r1,#1 (VERIFY_OPTIONAL) @0x0806052E")

print("\n== RESOLVED PnC CA cert store (C013, Agent N + byte-verification) ==")
print("  TWO stores: ext-SPI master hdr@0x1F8000 (magic 0xCEA155E1 / version1 / size / byte-sum),")
print("  data@0x1F8010; internal A/B 0x0800C000/0x08010000 (tail 0xCEA2AAE1). Entry 808B")
print("  {msg_code, der_len<=800, DER}. refresh 0x0805184C validates hdr; populate 0x080515CC")
print("  builds a compact NULL-term Root(0x8101) ptr-array @0x20018A48 (entry+4 = {len,DER}),")
print("  count -> 0x20018A64 (the SDP No-TLS gate). getter 0x08051ADC -> caller 0x080208CA ->")
print("  mbedTLS setup 0x080604D2 (x509_crt_parse + ssl_conf_ca_chain + authmode arg1==0 -> 2")
print("  VERIFY_REQUIRED). CORRECTION: prior anchors 0x08050E14/0x08050B94/0x08051074/0x0804EB5C")
print("  were GARBLED; real cluster 0x080515CC/0x0805184C/0x08051500/0x0805159C/0x08051526/")
print("  0x0804F58E/0x08051AAC. Replicated INERT in src/ca_store.c (ext-SPI -> RAM ptr-array, NO")
print("  internal A/B management, NO power GPIO). host test_ca_store 45 checks. X509 parse = Agent M.")

print(f"\n{checks} checks, {failures} failures")
sys.exit(1 if failures else 0)
