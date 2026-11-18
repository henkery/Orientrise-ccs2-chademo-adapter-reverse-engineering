#!/usr/bin/env python3
"""Robust entry-region disasm: skip undecodable halfwords, reveal true alignment.
Also test the msr encoding and dump halfwords. Usage: python3 analyze46.py firmware.bin"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
BASE=0x08020000
dec=open(sys.argv[1],'rb').read()
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True

print("== msr encoding test ==")
for i in md.disasm(bytes.fromhex('80f30888 80f30988'.replace(' ','')),0x08020412):
    print(f"   0x{i.address:08x}: {i.mnemonic} {i.op_str}")

print("== halfwords 0x400..0x460 ==")
for off in range(0x400,0x460,2):
    h=struct.unpack_from('<H',dec,off)[0]
    print(f"   f+0x{off:03x}: {h:04x}")

print("== robust disasm 0x400..0x560 (skip bad halfwords) ==")
off=0x400
while off<0x560:
    got=list(md.disasm(dec[off:off+4],BASE+off))
    if got:
        i=got[0]
        print(f"   0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}")
        off+=i.size
    else:
        print(f"   f+0x{off:06x}: <bad {struct.unpack_from('<H',dec,off)[0]:04x}>")
        off+=2
