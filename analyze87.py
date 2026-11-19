#!/usr/bin/env python3
"""analyze87.py — CHAdeMO RX message-parse decoder (§5.8.4/§5.18/§5.21, custom_fw CAN1 layer).
Decodes the C013 H100/H101/H102 receive parse from bytes: the CAN-ID dispatch, the little-endian
halfword helper, and each message's CAN-data-byte -> stm-context-field stores. This is the
byte-derived ground truth the custom firmware's chademo.c parse reproduces.

The RX frame buffer (stm context p[+0x260]) carries a 4-byte ID header (word0 = ID/RTR/IDE packed,
§5.8.2 mailbox layout), so CAN data byte N lives at buffer offset 4+N. The halfword helper
0x08050976 = `ldrb r1,[r0,#1]; ldrb r0,[r0]; add r0,r0,r1,lsl#8` => little-endian u16 (b0|b1<<8).

H102 (0x102) handler 0x0803BB72 (dispatched by `cmp r0,#0x102`):
  CAN byte0 (buf[4])      -> p[+0x1d8] status byte
  CAN byte1-2 (buf[5..6]) -> p[+0x1da] TargetBatteryVoltage (V, LE u16)
  CAN byte3 (buf[7])      -> p[+0x1dc] ChargingCurrentRequest (A)
  CAN byte4 (buf[8])      -> p[+0x1dd] fault byte (bfi/ubfx 1:1 bit copy)
  CAN byte5 (buf[9])      -> p[+0x1de] fault byte
  (Matches §5.8.4 "102.4/102.5 = byte4/5 fault". The §5.10 raw-frame note tentatively put the
   current request at byte0; the byte-derived parse places it at byte3 — parse is authoritative.)

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze87.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def rt(f): return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))

print("== 1. little-endian halfword helper 0x08050976 ==")
a = 0x08050976 - TB
for _ in range(4):
    ins = dis(a)
    if not ins: break
    i = ins[0]; print(f"  0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}"); a += i.size
print("  => u16 = buf[0] | buf[1]<<8  (little-endian)")

print("\n== 2. H102 context-store sites (strh [rX,#0x1da] / strb [rX,#0x1dc/0x1d8]) ==")
# wide STRH imm: hw1&0xFFF0==0xF8A0 ; wide STRB imm: hw1&0xFFF0==0xF880 ; imm12=hw2&0xFFF
targets = {0x1DA:'TargetBatteryVoltage', 0x1DC:'ChargingCurrentRequest', 0x1D8:'status'}
h102_site = None
for o in range(0, N-4, 2):
    h1 = u16(o); h2 = u16(o+2); op = h1 & 0xFFF0
    if op in (0xF8A0, 0xF880) and (h2 & 0xFFF) in targets:
        ins = dis(o)
        if ins and '[r4' in ins[0].op_str:
            imm = h2 & 0xFFF
            print(f"  f+0x{o:05x} 0x{rt(o):08X}: {ins[0].mnemonic:8s} {ins[0].op_str:24s} ; {targets[imm]}")
            if imm == 0x1DA and h102_site is None: h102_site = o

print("\n== 3. H102 handler 0x0803BB72 — CAN-byte -> field (buf offset = 4 + CAN byte) ==")
# Scan linearly across the handler incl. the branch target 0x803BBC0 (current request + faults);
# the literal pool between 0x803BB98..0x803BBBF disassembles as ldrsb garbage that matches no
# ldrb/strb [r4] pattern, so it is skipped naturally.
a = 0x0803BB72 - TB
end = 0x0803BC68 - TB
field_by_buf = {}
last_load = 0
while a < end:
    ins = dis(a)
    if not ins: a += 2; continue
    i = ins[0]; ops = i.operands; mn = i.mnemonic
    if mn in ('ldrb','ldrb.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.base!=70:
        last_load = ops[1].mem.disp   # CAN-data load (base r0 buffer); skip context reads (base r4)
    if mn in ('strb','strb.w','strh','strh.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.base==70:
        ctx = ops[1].mem.disp
        if ctx in (0x1d8,0x1da,0x1dc,0x1dd,0x1de) and ctx not in field_by_buf:
            field_by_buf[ctx] = last_load if mn.startswith('strb') else 'LE16'
    a += i.size
names = {0x1d8:'status', 0x1da:'TargetBatteryVoltage(V)', 0x1dc:'ChargingCurrentRequest(A)',
         0x1dd:'fault byte4', 0x1de:'fault byte5'}
for ctx in sorted(field_by_buf):
    src = field_by_buf[ctx]
    if src == 'LE16':
        print(f"  CAN byte1-2 (buf[5..6], LE) -> p[+0x{ctx:03x}] {names.get(ctx,'')}")
    else:
        print(f"  CAN byte{src-4} (buf[{src}]) -> p[+0x{ctx:03x}] {names.get(ctx,'')}")

print("\n== RESOLVED CHAdeMO RX parse (custom_fw chademo.c) ==")
print("  H102(0x102): byte0=status, byte1-2=TargetBatteryVoltage(V,LE), byte3=ChargingCurrentRequest(A),")
print("               byte4/byte5=fault bytes. H101(0x101): byte0/1=status, byte2-3 & byte4-5=LE u16,")
print("               byte6/7=status (p+0x1ba/1bb/1bc/1be/1c0/1c1). H100(0x100): vehicle status (raw).")
print("  Frame buffer p[+0x260] has a 4-byte ID header => CAN byte N = buf[4+N]; halfwords LE (0x08050976).")
