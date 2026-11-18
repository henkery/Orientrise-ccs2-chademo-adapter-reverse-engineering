#!/usr/bin/env python3
"""Bootloader->app ENTRY contract (REPORT 3.4/4.1/5.6), fast table-driven CRCs.

File 0x400 is not a valid Thumb start; first 4 bytes differ per revision and real
startup (cpsid i; set MSP/PSP; two .bss zero-fill loops; relocation) begins 0x40A.
Tests what the first-4-bytes / last-4-bytes trailer / footer u16 are (checksum?),
and disassembles the entry + resolves literal pools and BL targets.

Usage: python3 analyze45.py firmware.bin [decoded_c013.bin]
"""
import sys, struct, zlib
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
BASE = 0x08020000

def mk_table(poly, refin):
    tab=[]
    for i in range(256):
        if refin:
            c=i
            for _ in range(8): c=(c>>1)^(poly if c&1 else 0)
        else:
            c=i<<24
            for _ in range(8): c=((c<<1)^poly)&0xFFFFFFFF if c&0x80000000 else (c<<1)&0xFFFFFFFF
        tab.append(c)
    return tab

def crc32_tab(data, tab, init, refin, refout, xorout):
    crc=init
    if refin:
        for b in data: crc=(crc>>8)^tab[(crc^b)&0xFF]
    else:
        for b in data: crc=((crc<<8)&0xFFFFFFFF)^tab[((crc>>24)^b)&0xFF]
    if refout!=refin:
        r=0
        for _ in range(32): r=(r<<1)|(crc&1); crc>>=1
        crc=r
    return crc^xorout

P32=0x04C11DB7; P32R=0xEDB88320; PC32=0x1EDC6F41; PC32R=0x82F63B78
T_FWD=mk_table(P32,False); T_REV=mk_table(P32R,True)
TC_FWD=mk_table(PC32,False); TC_REV=mk_table(PC32R,True)
def crc32s(d):
    return {
        'CRC32':crc32_tab(d,T_REV,0xFFFFFFFF,True,True,0xFFFFFFFF),
        'CRC32/BZIP2':crc32_tab(d,T_FWD,0xFFFFFFFF,False,False,0xFFFFFFFF),
        'CRC32/MPEG2':crc32_tab(d,T_FWD,0xFFFFFFFF,False,False,0),
        'CRC32/JAM':crc32_tab(d,T_REV,0xFFFFFFFF,True,True,0),
        'CRC32/POSIX':crc32_tab(d,T_FWD,0,False,False,0xFFFFFFFF),
        'CRC32C':crc32_tab(d,TC_REV,0xFFFFFFFF,True,True,0xFFFFFFFF),
        'CRC32C/JAM':crc32_tab(d,TC_REV,0xFFFFFFFF,True,True,0),
    }

def mk16(poly,refin):
    tab=[]
    for i in range(256):
        if refin:
            c=i
            for _ in range(8): c=(c>>1)^(poly if c&1 else 0)
        else:
            c=i<<8
            for _ in range(8): c=((c<<1)^poly)&0xFFFF if c&0x8000 else (c<<1)&0xFFFF
        tab.append(c)
    return tab
def crc16_tab(d,tab,init,refin,refout,xorout):
    crc=init
    if refin:
        for b in d: crc=(crc>>8)^tab[(crc^b)&0xFF]
    else:
        for b in d: crc=((crc<<8)&0xFFFF)^tab[((crc>>8)^b)&0xFF]
    if refout!=refin:
        r=0
        for _ in range(16): r=(r<<1)|(crc&1); crc>>=1
        crc=r
    return crc^xorout
C16=[('CCITT-FALSE',0x1021,0xFFFF,False,False,0),('XMODEM',0x1021,0,False,False,0),
     ('KERMIT',0x1021,0,True,True,0),('X-25',0x1021,0xFFFF,True,True,0xFFFF),
     ('MODBUS',0x8005,0xFFFF,True,True,0),('ARC',0x8005,0,True,True,0),
     ('MAXIM',0x8005,0,True,True,0xFFFF),('USB',0x8005,0xFFFF,True,True,0xFFFF),
     ('DNP',0x3D65,0,True,True,0xFFFF),('T10-DIF',0x8BB7,0,False,False,0),
     ('CRC-A',0x1021,0xC6C6,True,True,0),('RIELLO',0x1021,0xB2AA,True,True,0),
     ('TMS37157',0x1021,0x89EC,True,True,0),('AUG-CCITT',0x1021,0x1D0F,False,False,0)]
T16={(p,r):mk16(p,r) for _,p,_,r,_,_ in C16}

def regions(dec):
    n=len(dec)
    return {'[404:n-4]':dec[0x404:n-4],'[404:n]':dec[0x404:n],'[40A:n-4]':dec[0x40A:n-4],
            '[40A:n]':dec[0x40A:n],'[400:n-4]':dec[0x400:n-4],'[400:n]':dec[0x400:n],
            '[58:n-4]':dec[0x58:n-4],'[404:n-2]':dec[0x404:n-2],'[40A:n-2]':dec[0x40A:n-2],
            '[400:404]+[404:n-4]':dec[0x400:n-4]}

def folds(d):
    s32=0; x32=0
    for i in range(0,len(d)-3,4):
        w=struct.unpack_from('<I',d,i)[0]; s32=(s32+w)&0xFFFFFFFF; x32^=w
    s16=sum(d)&0xFFFF
    return {'sum32':s32,'xor32':x32,'sum16':s16,'sum32hi':s32>>16,'sum32lo':s32&0xFFFF}

def analyze(dec,label):
    n=len(dec)
    first4=struct.unpack_from('<I',dec,0x400)[0]
    trail4=struct.unpack_from('<I',dec,n-4)[0]
    trail_hi=struct.unpack_from('>H',dec,n-2)[0]
    foot16=struct.unpack_from('<H',dec,0x3FE)[0]
    print(f"== {label} n={n} first4=0x{first4:08X} trailer=0x{trail4:08X}(hi16=0x{trail_hi:04X}) footer=0x{foot16:04X}")
    for rn,rd in regions(dec).items():
        c32=crc32s(rd); f=folds(rd)
        for cn,v in c32.items():
            if v==first4: print(f"   [first4=MATCH] {cn}({rn})")
            if v==trail4: print(f"   [trailer=MATCH] {cn}({rn})")
        for fn,v in f.items():
            if v==first4: print(f"   [first4=MATCH] {fn}({rn})")
            if v==trail4: print(f"   [trailer=MATCH] {fn}({rn})")
            if v==trail_hi: print(f"   [trailer_hi=MATCH] {fn}({rn})")
            if v==foot16: print(f"   [footer=MATCH] {fn}({rn})")
        for cn,p,init,ri,ro,xo in C16:
            v=crc16_tab(rd,T16[(p,ri)],init,ri,ro,xo)
            if v==trail_hi: print(f"   [trailer_hi=MATCH] crc16/{cn}({rn})")
            if v==foot16: print(f"   [footer=MATCH] crc16/{cn}({rn})")
            if v==first4&0xFFFF: print(f"   [first4lo=MATCH] crc16/{cn}({rn})")
    print("   (no MATCH lines above => none of the standard CRC/sum hypotheses fit)")

def disasm(dec):
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
    print("== entry disasm 0x40A..0x560 ==")
    for i in md.disasm(dec[0x40A:0x560],BASE+0x40A):
        print(f"   0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}")
    print("== literal pool words ==")
    for off in (0x44C,0x450,0x454,0x458,0x45C):
        print(f"   word@0x{off:03X} = 0x{struct.unpack_from('<I',dec,off)[0]:08X}")
    print("== BL targets prologues ==")
    for t in (0x675D8,0x534,0x67BD8):
        print(f"   --- f+0x{t:05X} ---")
        for i in md.disasm(dec[t:t+16],BASE+t):
            print(f"      0x{i.address:08x}: {i.mnemonic:9s} {i.op_str}")

def main():
    dec=open(sys.argv[1],'rb').read()
    analyze(dec,sys.argv[1]); disasm(dec)
    if len(sys.argv)>2:
        analyze(open(sys.argv[2],'rb').read(),sys.argv[2])

if __name__=='__main__':
    main()
