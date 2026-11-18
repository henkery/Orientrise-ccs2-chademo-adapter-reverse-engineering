#!/usr/bin/env python3
"""Deep integrity-check hunt for the UPG entry header/trailer/footer (REPORT 4.1).
first4@0x400, trailer@n-4, footer u16@0x3FE are NOT standard CRCs of the obvious
decoded regions. Try RAW (XOR-obfuscated) bytes, 0xFF-padded-to-sector regions,
and both endiannesses of the trailer u16. Fast table-driven CRCs.
Usage: python3 analyze47.py <raw.UPG> <decoded.bin>"""
import sys, struct, zlib
raw=open(sys.argv[1],'rb').read(); dec=open(sys.argv[2],'rb').read(); n=len(dec)
first4=struct.unpack_from('<I',dec,0x400)[0]
tr_le=struct.unpack_from('<H',dec,n-2)[0]; tr_be=struct.unpack_from('>H',dec,n-2)[0]
tr4=struct.unpack_from('<I',dec,n-4)[0]
foot=struct.unpack_from('<H',dec,0x3FE)[0]
print(f"first4=0x{first4:08X} trailer4=0x{tr4:08X} trLE=0x{tr_le:04X} trBE=0x{tr_be:04X} footer=0x{foot:04X}")

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
P=0x04C11DB7; PR=0xEDB88320; PC=0x1EDC6F41; PCR=0x82F63B78
TF=mk32(P,False); TR=mk32(PR,True); TCF=mk32(PC,False); TCR=mk32(PCR,True)
def crc32s(d):
    return {'CRC32':c32(d,TR,0xFFFFFFFF,True,True,0xFFFFFFFF),
            'BZIP2':c32(d,TF,0xFFFFFFFF,False,False,0xFFFFFFFF),
            'MPEG2':c32(d,TF,0xFFFFFFFF,False,False,0),
            'JAM':c32(d,TR,0xFFFFFFFF,True,True,0),
            'POSIX':c32(d,TF,0,False,False,0xFFFFFFFF),
            'CRC32C':c32(d,TCR,0xFFFFFFFF,True,True,0xFFFFFFFF),
            'CRC32C/JAM':c32(d,TCR,0xFFFFFFFF,True,True,0),
            'CRC32/0init':c32(d,TR,0,True,True,0xFFFFFFFF),
            'CRC32/nofinal':c32(d,TR,0xFFFFFFFF,True,True,0)}
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
C16=[('CCITT-FALSE',0x1021,0xFFFF,False,False,0),('XMODEM',0x1021,0,False,False,0),
     ('KERMIT',0x1021,0,True,True,0),('X-25',0x1021,0xFFFF,True,True,0xFFFF),
     ('MODBUS',0x8005,0xFFFF,True,True,0),('ARC',0x8005,0,True,True,0),
     ('MAXIM',0x8005,0,True,True,0xFFFF),('USB',0x8005,0xFFFF,True,True,0xFFFF),
     ('DNP',0x3D65,0,True,True,0xFFFF),('T10-DIF',0x8BB7,0,False,False,0),
     ('CRC-A',0x1021,0xC6C6,True,True,0),('RIELLO',0x1021,0xB2AA,True,True,0),
     ('TMS37157',0x1021,0x89EC,True,True,0),('AUG-CCITT',0x1021,0x1D0F,False,False,0),
     ('GENIBUS',0x1021,0xFFFF,False,False,0xFFFF),('PROFIBUS',0x1DCF,0xFFFF,False,False,0xFFFF)]
T16={(p,r):mk16(p,r) for _,p,_,r,_,_ in C16}

def pad(d,boundary):
    r=len(d)%boundary
    return d if r==0 else d+b'\xff'*(boundary-r)

regs={}
for name,src in (('dec',dec),('raw',raw)):
    regs[f'{name}[404:n-4]']=src[0x404:n-4]
    regs[f'{name}[404:n]']=src[0x404:n]
    regs[f'{name}[400:n-4]']=src[0x400:n-4]
    regs[f'{name}[40A:n-4]']=src[0x40A:n-4]
    regs[f'{name}[58:3EA]']=src[0x58:0x3EA]
    regs[f'{name}[404:n-4]pad16']=pad(src[0x404:n-4],16)
    regs[f'{name}[404:n-4]pad4']=pad(src[0x404:n-4],4)
# sector-padded code (app sectors 5-9 end at 0x080C0000 => file 0xA0000)
regs['dec[404:n-4]padTo0xA0000']=dec[0x404:n-4]+b'\xff'*(0xA0000-0x404-(n-4)) if n-4<0xA0000 else dec[0x404:n-4]

print("== first4 / trailer4 as CRC32 ==")
hit=False
for rn,rd in regs.items():
    for cn,v in crc32s(rd).items():
        if v==first4: print(f"  [first4] {cn}({rn})"); hit=True
        if v==tr4: print(f"  [trailer4] {cn}({rn})"); hit=True
if not hit: print("  none")
print("== trailer u16 (LE/BE) / footer as CRC16 ==")
hit=False
for rn,rd in regs.items():
    for cn,p,init,ri,ro,xo in C16:
        v=c16(rd,T16[(p,ri)],init,ri,ro,xo)
        if v==tr_le: print(f"  [trLE] crc16/{cn}({rn})"); hit=True
        if v==tr_be: print(f"  [trBE] crc16/{cn}({rn})"); hit=True
        if v==foot: print(f"  [footer] crc16/{cn}({rn})"); hit=True
if not hit: print("  none")
print("== simple folds of dec[404:n-4] ==")
d=dec[0x404:n-4]
s=sum(d); x=0
for b in d: x^=b
s32=0;x32=0
for i in range(0,len(d)-3,4):
    w=struct.unpack_from('<I',d,i)[0]; s32=(s32+w)&0xFFFFFFFF; x32^=w
print(f"  sum8=0x{s&0xFF:02X} sum16=0x{s&0xFFFF:04X} sum32=0x{s32:08X} xor8=0x{x:02X} xor32=0x{x32:08X}")
print(f"  targets: first4=0x{first4:08X} trLE=0x{tr_le:04X} trBE=0x{tr_be:04X} footer=0x{foot:04X}")
