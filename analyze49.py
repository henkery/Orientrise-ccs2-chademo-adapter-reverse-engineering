#!/usr/bin/env python3
"""Verify the trailer XOR-fold checksum across revisions + pin region/width.
analyze47 found xor8(dec[404:n-4])==trailer byte[n-2] for C009. Confirm on C013 and
test xor8/xor16 over candidate regions; also re-test first4 as prefix checksums.
Usage: python3 analyze49.py firmware.bin decoded_c013.bin"""
import sys, struct, zlib
def xor8(d):
    x=0
    for b in d: x^=b
    return x
def xor16(d):
    x=0
    for i in range(0,len(d)-1,2): x^=d[i]|(d[i+1]<<8)
    if len(d)&1: x^=d[-1]
    return x
def sum16(d): return sum(d)&0xFFFF
for path in sys.argv[1:]:
    dec=open(path,'rb').read(); n=len(dec)
    first4=struct.unpack_from('<I',dec,0x400)[0]
    tr=dec[n-4:]
    print(f"== {path} n={n} first4=0x{first4:08X} trailer={tr.hex(' ')}")
    cands={'[404:n-4]':dec[0x404:n-4],'[400:n-4]':dec[0x400:n-4],'[404:n-2]':dec[0x404:n-2],
           '[400:n-2]':dec[0x400:n-2],'[40A:n-4]':dec[0x40A:n-4],'[404:n]':dec[0x404:n],
           '[400:n]':dec[0x400:n],'[404:n-3]':dec[0x404:n-3]}
    for rn,rd in cands.items():
        x8=xor8(rd); x16=xor16(rd); s16=sum16(rd)
        m=[]
        if x8==tr[2]: m.append(f"xor8==tr[2](0x{tr[2]:02X})")
        if x8==tr[0]: m.append(f"xor8==tr[0]")
        if x16==struct.unpack_from('<H',tr,2)[0]: m.append(f"xor16==trLE@2(0x{struct.unpack_from('<H',tr,2)[0]:04X})")
        if x16==struct.unpack_from('<H',tr,0)[0]: m.append(f"xor16==trLE@0")
        if s16==struct.unpack_from('<H',tr,2)[0]: m.append(f"sum16==trLE@2")
        print(f"   {rn:12s} xor8=0x{x8:02X} xor16=0x{x16:04X} sum16=0x{s16:04X}  {'; '.join(m) if m else ''}")
    # first4 as checksum of prefix / header
    for rn,rd in {'prefix[58:3EA]':dec[0x58:0x3EA],'hdr[0:58]':dec[0:0x58],'hdr+prefix[0:3EA]':dec[0:0x3EA]}.items():
        c=zlib.crc32(rd)&0xFFFFFFFF
        print(f"   first4 vs crc32({rn})=0x{c:08X} {'MATCH' if c==first4 else ''}  xor8=0x{xor8(rd):02X} sum16=0x{sum16(rd):04X}")
