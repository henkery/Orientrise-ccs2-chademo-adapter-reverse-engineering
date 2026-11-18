#!/usr/bin/env python3
"""Locate the usbdisk UPG update orchestration; determine raw-vs-decoded flash write.
Xrefs the UPG filename / update-status strings (ADR/LDR-literal/movw-movt), then
disassembles the referencing functions to see the read->flash-write loop and whether
any XOR/transform is applied before writing. Usage: python3 analyze48.py firmware.bin"""
import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
dec=open(sys.argv[1],'rb').read(); n=len(dec); BASE=0x08020000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def imm16(h1,h2): return (((h1>>4)&0xF)<<12)|(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
const=collections.defaultdict(list); adr=collections.defaultdict(list); last={}
for a in range(0x400,n-4,2):
    h1=struct.unpack_from('<H',dec,a)[0]; h2=struct.unpack_from('<H',dec,a+2)[0]
    if (h1&0xFBF0)==0xF240: last[(h2>>8)&0xF]=(a,imm16(h1,h2))
    elif (h1&0xFBF0)==0xF2C0:
        rd=(h2>>8)&0xF
        if rd in last:
            pa,lo=last[rd]
            if a-pa<=12: const[(imm16(h1,h2)<<16)|lo].append(('movw/movt',pa))
            del last[rd]
    if (h1&0xFF7F)==0xF85F:
        u=(h1>>7)&1; t=((a+4)&~3)+((h2&0xFFF) if u else -(h2&0xFFF))
        if 0<=t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldrT2',a))
    if (h1&0xF800)==0x4800:
        t=((a+4)&~3)+(h1&0xFF)*4
        if t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldrT1',a))
    if (h1&0xF800)==0xA000:
        t=((a+4)&~3)+(h1&0xFF)*4
        if t<n: adr[BASE+t].append(('adrT1',a))
    if (h1&0xFBFF)==0xF20F:
        imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF); t=((a+4)&~3)+imm
        if t<n: adr[BASE+t].append(('adrT3+',a))
    elif (h1&0xFBFF)==0xF2AF:
        imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF); t=((a+4)&~3)-imm
        if 0<=t<n: adr[BASE+t].append(('adrT3-',a))

targets={0x030102:'BOOT_…UPG',0x03011a:'MAIN_…UPG',0x030132:'MAIN_…ID6.UPG',
         0x02ffee:'Write flash error[%u]',0x02ff76:"'%s' has been updated",
         0x03001a:'[%t]UPGRADE Finished',0x030062:"'%s' has been downloaded",
         0x030d72:'UPGRADE:[%u]…'}
sites=[]
for off,name in targets.items():
    v=BASE+off
    hits=adr.get(v,[])+[('const',o) for k,o in const.get(v,[])]
    print(f"== {name} (f+0x{off:06x}): {len(hits)} xref(s)")
    for k,o in hits:
        print(f"     {k} @ f+0x{o:06x}")
        sites.append(o)

print("\n== disasm around each xref (function context) ==")
seen=set()
for o in sorted(set(sites)):
    # back up to a plausible function start (push) within 0x80 bytes
    start=o
    for b in range(o,max(0x400,o-0x80),-2):
        h=struct.unpack_from('<H',dec,b)[0]
        if (h&0xFF00)==0xB500 or (h&0xFE00)==0xE920:  # push {..,lr} / stmdb sp!
            start=b; break
    if start in seen: continue
    seen.add(start)
    print(f"--- context f+0x{start:06x} (xref f+0x{o:06x}) ---")
    for i in md.disasm(dec[start:start+0x90],BASE+start):
        print(f"   0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}")
