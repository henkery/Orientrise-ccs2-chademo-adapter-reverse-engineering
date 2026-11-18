#!/usr/bin/env python3
"""Final integrity-field crack: first4@0x400, trailer@n-4, footer u16@0x3FE.
Tries Adler32, CRC32 (many setups) and CRC16 (many polys) over CODE and PREFIX
regions, decoded AND raw, to learn whether the checks cover the code (blocks a
service-firmware rewrite) or only the prefix (reusable verbatim).
Usage: python3 analyze50.py <raw.UPG> <decoded.bin>"""
import sys, struct, zlib
raw=open(sys.argv[1],'rb').read(); dec=open(sys.argv[2],'rb').read(); n=len(dec)
first4=struct.unpack_from('<I',dec,0x400)[0]
tr4=struct.unpack_from('<I',dec,n-4)[0]
tr_hi=struct.unpack_from('>H',dec,n-2)[0]; tr_lo=struct.unpack_from('<H',dec,n-2)[0]
foot=struct.unpack_from('<H',dec,0x3FE)[0]
print(f"first4=0x{first4:08X} tr4=0x{tr4:08X} tr_hiBE=0x{tr_hi:04X} tr_loLE=0x{tr_lo:04X} footer=0x{foot:04X}")

def mk32(poly,refin):
    t=[]
    for i in range(256):
        if refin:
            c=i
            for _ in range(8): c=(c>>1)^(poly if c&1 else 0)
        else:
            c=i<<24
            for _ in range(8): c=((c<<1)^poly)&0xFFFFFFFF if c&0x80000000 else (c<<1)&0xFFFFFFFF
        t.append(c)
    return t
def c32(d,t,init,refin,refout,xo):
    c=init
    if refin:
        for b in d: c=(c>>8)^t[(c^b)&0xFF]
    else:
        for b in d: c=((c<<8)&0xFFFFFFFF)^t[((c>>24)^b)&0xFF]
    if refout!=refin:
        r=0
        for _ in range(32): r=(r<<1)|(c&1); c>>=1
        c=r
    return c^xo
P=0x04C11DB7;PR=0xEDB88320;PC=0x1EDC6F41;PCR=0x82F63B78
TF=mk32(P,False);TR=mk32(PR,True);TCF=mk32(PC,False);TCR=mk32(PCR,True)
def crc32s(d):
    return {'CRC32':c32(d,TR,0xFFFFFFFF,True,True,0xFFFFFFFF),'BZIP2':c32(d,TF,0xFFFFFFFF,False,False,0xFFFFFFFF),
            'MPEG2':c32(d,TF,0xFFFFFFFF,False,False,0),'JAM':c32(d,TR,0xFFFFFFFF,True,True,0),
            'POSIX':c32(d,TF,0,False,False,0xFFFFFFFF),'CRC32C':c32(d,TCR,0xFFFFFFFF,True,True,0xFFFFFFFF),
            'CRC32C/JAM':c32(d,TCR,0xFFFFFFFF,True,True,0),'CRC32/0':c32(d,TR,0,True,True,0xFFFFFFFF),
            'CRC32/nofinal':c32(d,TR,0xFFFFFFFF,True,True,0),'CRC32C/0':c32(d,TCR,0,True,True,0xFFFFFFFF)}
def mk16(poly,refin):
    t=[]
    for i in range(256):
        if refin:
            c=i
            for _ in range(8): c=(c>>1)^(poly if c&1 else 0)
        else:
            c=i<<8
            for _ in range(8): c=((c<<1)^poly)&0xFFFF if c&0x8000 else (c<<1)&0xFFFF
        t.append(c)
    return t
def c16(d,t,init,refin,refout,xo):
    c=init
    if refin:
        for b in d: c=(c>>8)^t[(c^b)&0xFF]
    else:
        for b in d: c=((c<<8)&0xFFFF)^t[((c>>8)^b)&0xFF]
    if refout!=refin:
        r=0
        for _ in range(16): r=(r<<1)|(c&1); c>>=1
        c=r
    return c^xo
C16=[('CCITT-FALSE',0x1021,0xFFFF,False,False,0),('XMODEM',0x1021,0,False,False,0),('KERMIT',0x1021,0,True,True,0),
     ('X-25',0x1021,0xFFFF,True,True,0xFFFF),('MODBUS',0x8005,0xFFFF,True,True,0),('ARC',0x8005,0,True,True,0),
     ('MAXIM',0x8005,0,True,True,0xFFFF),('USB',0x8005,0xFFFF,True,True,0xFFFF),('DNP',0x3D65,0,True,True,0xFFFF),
     ('T10-DIF',0x8BB7,0,False,False,0),('CRC-A',0x1021,0xC6C6,True,True,0),('RIELLO',0x1021,0xB2AA,True,True,0),
     ('TMS37157',0x1021,0x89EC,True,True,0),('AUG-CCITT',0x1021,0x1D0F,False,False,0),('GENIBUS',0x1021,0xFFFF,False,False,0xFFFF),
     ('PROFIBUS',0x1DCF,0xFFFF,False,False,0xFFFF),('MCRF4XX',0x1021,0xFFFF,True,True,0),('DECT',0x0589,0,False,False,0x0001)]
T16={(p,r):mk16(p,r) for _,p,_,r,_,_ in C16}

regs={}
for name,src in (('dec',dec),('raw',raw)):
    for a,b,tag in [(0x404,n-4,'code[404:n-4]'),(0x400,n-4,'code[400:n-4]'),(0x40A,n-4,'code[40A:n-4]'),
                    (0x58,0x3EA,'prefix[58:3EA]'),(0x00,0x3EA,'hdr+prefix[0:3EA]'),(0x404,n,'code[404:n]'),
                    (0x00,n-4,'img[0:n-4]'),(0x58,n-4,'prefix+code[58:n-4]')]:
        regs[f'{name}.{tag}']=src[a:b]
print("== first4 / tr4 as CRC32 or Adler32 =="); hit=False
for rn,rd in regs.items():
    ad=zlib.adler32(rd)&0xFFFFFFFF
    if ad==first4: print(f"  [first4] Adler32({rn})"); hit=True
    if ad==tr4: print(f"  [tr4] Adler32({rn})"); hit=True
    for cn,v in crc32s(rd).items():
        if v==first4: print(f"  [first4] {cn}({rn})"); hit=True
        if v==tr4: print(f"  [tr4] {cn}({rn})"); hit=True
if not hit: print("  none")
print("== tr_hi/tr_lo/footer as CRC16 =="); hit=False
for rn,rd in regs.items():
    for cn,p,init,ri,ro,xo in C16:
        v=c16(rd,T16[(p,ri)],init,ri,ro,xo)
        if v==tr_hi: print(f"  [tr_hiBE] crc16/{cn}({rn})"); hit=True
        if v==tr_lo: print(f"  [tr_loLE] crc16/{cn}({rn})"); hit=True
        if v==foot: print(f"  [footer] crc16/{cn}({rn})"); hit=True
if not hit: print("  none")
