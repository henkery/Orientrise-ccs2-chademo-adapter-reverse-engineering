#!/usr/bin/env python3
"""Confirm f_close (candidate 0x036a3c clears fp->obj.fs after a sync call) and its
f_sync target; inspect the app-code tail (flash writer .. end) to choose a cave site;
report exact app end + unused sector-9 tail available for an appended cave.
Usage: nix-shell -p python3 python3Packages.capstone --run 'python3 analyze65.py firmware.bin'
"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
def u32(o): return struct.unpack_from('<I', dec, o)[0]
def bl_target(a):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 >> 11) != 0x1E or (h2 & 0xD000) != 0xD000: return None
    S=(h1>>10)&1; imm10=h1&0x3FF; J1=(h2>>13)&1; J2=(h2>>11)&1; imm11=h2&0x7FF
    I1=1-((J1^S)&1); I2=1-((J2^S)&1)
    off=(S<<24)|(I1<<23)|(I2<<22)|(imm10<<12)|(imm11<<1)
    if off&(1<<24): off-=1<<25
    return (a+4)+off
def disasm(start,end,label,maxins=200):
    print(f"\n--- {label}: f+0x{start:06x}..f+0x{end:06x} ---")
    a=start;cnt=0
    while a<end and cnt<maxins:
        ins=list(md.disasm(dec[a:a+4],BASE+a,count=1))
        if not ins:
            print(f"  f+0x{a:06x}: .hword 0x{struct.unpack_from('<H',dec,a)[0]:04x} (bad)");a+=2;continue
        i=ins[0];h1=struct.unpack_from('<H',dec,a)[0];note=''
        if i.mnemonic=='bl':
            t=bl_target(a)
            if t is not None: note=f"   -> f+0x{t:06x}"
        elif (h1&0xFF7F)==0xF85F and i.size==4:
            h2=struct.unpack_from('<H',dec,a+2)[0];u=(h1>>7)&1
            t=((a+4)&~3)+((h2&0xFFF) if u else -(h2&0xFFF))
            if 0<=t<n-3: note=f"   [pool@f+0x{t:06x}=0x{u32(t):08X}]"
        elif (h1&0xF800)==0x4800:
            t=((a+4)&~3)+(h1&0xFF)*4
            if t<n-3: note=f"   [pool@f+0x{t:06x}=0x{u32(t):08X}]"
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}{note}")
        a+=i.size;cnt+=1
disasm(0x036a3c,0x036a9c,"f_close candidate 0x036a3c (full)")
disasm(0x036a9c,0x036ab0,"next func 0x036a9c")
# app tail
print(f"\n== app geometry ==")
print(f"  decoded size n=0x{n:x} ({n}); trailer f+0x{n-4:06x}..f+0x{n:06x}")
print(f"  app code f+0x40a..f+0x{n-4:06x}; length field@0x3f2=0x{u32(0x3f2):x} (n-0x404=0x{n-0x404:x})")
print(f"  app end runtime=0x{BASE+n-4:08x}; sector9 end=0x080C0000 (file 0xA0000)")
print(f"  unused sector-9 tail: file 0x{n-4:06x}..0xA0000 = {0xA0000-(n-4)} bytes")
disasm(0x911e0,0x914c4,"app tail after flash-writer tables",maxins=120)
