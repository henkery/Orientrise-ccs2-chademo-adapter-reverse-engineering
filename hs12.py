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
def sites(v): return ", ".join(f"{k}@f+0x{o:06x}" for k,o in const.get(v,[])[:14]) or "(none)"
def disasm(off,length,label=""):
    print(f"--- disasm f+0x{off:06x}..+0x{length:x} {label} ---")
    for i in md.disasm(dec[off:off+length],BASE+off):
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:10s} {i.op_str}")
def hexdump(off,length):
    for a in range(off,off+length,16):
        row=dec[a:a+16]
        print(f"  f+0x{a:06x}: {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")
def word(off): return struct.unpack_from('<I',dec,off)[0]

print("== SDP global struct + 20-byte template ==")
for off in (0x000db0,0x000db4,0x002600):
    print(f"  word f+0x{off:06x} = 0x{word(off):08x}")
hexdump(0x000db4,0x20)
print("== MAC globals ==")
for v in (0x20000A00,0x200227E6,0x20003198):
    print(f"  0x{v:08x}: {sites(v)}")
print("\n== 'START SDP' string neighborhood f+0x000d4a ==")
for v in sorted(const):
    if BASE+0x000d40<=v<=BASE+0x000d60: print(f"  0x{v:08x}(f+0x{v-BASE:06x}): {sites(v)}")
print("\n== SLAC-SDP info MAC print context ==")
disasm(0x02e7c0,0xA0,"mac_addr print (adr@0x02e824)")
