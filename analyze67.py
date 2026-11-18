#!/usr/bin/env python3
"""Find f_sync / f_close among callers of validate(0x036368). f_sync(fp) calls validate
then checks fp->flag dirty/write and syncs the dir entry + FAT; f_close calls f_sync then
clears fp->obj.fs. List all BL callers of validate, disasm the small ones (<200 B) to
identify the finalizer the dump cave should call (f_close=0x036a9c only validates+clears).
Usage: nix-shell -p python3 python3Packages.capstone --run 'python3 analyze67.py firmware.bin'
"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
def bl_target(a):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 >> 11) != 0x1E or (h2 & 0xD000) != 0xD000: return None
    S=(h1>>10)&1; imm10=h1&0x3FF; J1=(h2>>13)&1; J2=(h2>>11)&1; imm11=h2&0x7FF
    I1=1-((J1^S)&1); I2=1-((J2^S)&1)
    off=(S<<24)|(I1<<23)|(I2<<22)|(imm10<<12)|(imm11<<1)
    if off&(1<<24): off-=1<<25
    return (a+4)+off
def disasm(start,end,label,maxins=120):
    print(f"\n--- {label}: f+0x{start:06x}..f+0x{end:06x} ---")
    a=start;cnt=0
    while a<end and cnt<maxins:
        ins=list(md.disasm(dec[a:a+4],BASE+a,count=1))
        if not ins:
            print(f"  f+0x{a:06x}: .hword 0x{struct.unpack_from('<H',dec,a)[0]:04x} (bad)");a+=2;continue
        i=ins[0];note=''
        if i.mnemonic=='bl':
            t=bl_target(a)
            if t is not None: note=f"   -> f+0x{t:06x}"
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}{note}")
        a+=i.size;cnt+=1
# function starts (push prologues) to bound enclosing functions
pro=[]
for a in range(0x034000,0x039200,2):
    h1=struct.unpack_from('<H',dec,a)[0]
    if h1==0xE92D or ((h1&0xFE00)==0xB400 and (h1&0x0100)): pro.append(a)
pro=sorted(set(pro))
def enclosing(off):
    for i,s in enumerate(pro):
        e=pro[i+1] if i+1<len(pro) else 0x039200
        if s<=off<e: return s,e
    return None
callers=[a for a in range(0x400,n-4,2) if bl_target(a)==0x036368]
print(f"== validate(0x036368) BL callers: {len(callers)} ==")
seen=set()
for c in callers:
    en=enclosing(c)
    if not en: continue
    s,e=en
    if s in seen: continue
    seen.add(s)
    print(f"  caller f+0x{c:06x} in func f+0x{s:06x} size~{e-s}")
# disasm small enclosing functions (f_sync/f_close candidates)
for s,e in sorted(seen and [(s, next((pro[i+1] if i+1<len(pro) else 0x039200) for i,x in enumerate(pro) if x==s)) for s in seen]):
    if e-s<=200:
        disasm(s,e,f"small validate-caller f+0x{s:06x}",maxins=90)
