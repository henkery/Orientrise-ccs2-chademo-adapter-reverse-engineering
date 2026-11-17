import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def imm16(h1,h2): return (((h1>>4)&0xF)<<12)|(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
const=collections.defaultdict(list); last={}
for a in range(0x400,n-4,2):
    h1=struct.unpack_from('<H',dec,a)[0]; h2=struct.unpack_from('<H',dec,a+2)[0]
    if (h1&0xFBF0)==0xF240: last[(h2>>8)&0xF]=(a,imm16(h1,h2))
    elif (h1&0xFBF0)==0xF2C0:
        rd=(h2>>8)&0xF
        if rd in last:
            pa,lo=last[rd]
            if a-pa<=12: const[(imm16(h1,h2)<<16)|lo].append(('mov',pa))
            del last[rd]
    if (h1&0xFF7F)==0xF85F:
        u=(h1>>7)&1; t=((a+4)&~3)+((h2&0xFFF) if u else -(h2&0xFFF))
        if 0<=t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldr2',a))
    if (h1&0xF800)==0x4800:
        t=((a+4)&~3)+(h1&0xFF)*4
        if t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldr1',a))
    if (h1&0xF800)==0xA000:
        t=((a+4)&~3)+(h1&0xFF)*4
        if t<n: const[BASE+t].append(('adr1',a))
    if (h1&0xFBFF)==0xF20F:
        imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF); t=((a+4)&~3)+imm
        if t<n: const[BASE+t].append(('adr2+',a))
    elif (h1&0xFBFF)==0xF2AF:
        imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF); t=((a+4)&~3)-imm
        if 0<=t<n: const[BASE+t].append(('adr2-',a))
def sites(v): return ", ".join(f"{k}@f+0x{o:06x}" for k,o in const.get(v,[])[:12]) or "(none)"
def hexdump(off,length):
    for a in range(off,off+length,16):
        row=dec[a:a+16]
        print(f"  f+0x{a:06x}: {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")

print("== validate ADR path: string at f+0x0144c0 (target of adr@0x0141f4) ==")
print("  0x080344c0:", sites(0x080344C0))
print("== RAM pointers used in records ==")
for v in (0x20003198,0x20000770,0x20000772,0x20000773):
    print(f"  0x{v:08x}: {sites(v)}")
print("== any const key landing in ns-pool neighborhood [0x08034200,0x08034400) ==")
for v in sorted(const):
    if 0x08034200<=v<0x08034400:
        print(f"  0x{v:08x} (f+0x{v-BASE:06x}): {sites(v)}")
print("== raw word search for record starts (any alignment) ==")
for soff in (0x014272,0x01491e,0x00f02e,0x01344a):
    v=BASE+soff; pat=struct.pack('<I',v); hits=[]; i=dec.find(pat)
    while i!=-1 and len(hits)<8: hits.append(i); i=dec.find(pat,i+1)
    print(f"  rec f+0x{soff:06x} (0x{v:08x}): "+(", ".join(f"f+0x{h:06x}" for h in hits) or "none"))
print("\n== hex after ns strings f+0x0142a8..0x014360 ==")
hexdump(0x0142a8,0xB8)
