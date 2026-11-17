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
    if (h1&0xFB7F)==0xF85F:
        u=(h1>>10)&1; t=((a+4)&~3)+((h2&0xFFF) if u else -(h2&0xFFF))
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
def nb(soff,span=10):
    out=[]
    for v in sorted(const):
        if BASE+soff-span<=v<=BASE+soff+span: out.append(f"f+0x{v-BASE:06x}:{sites(v)}")
    return " | ".join(out) or "none"

print("== STM32 UID / flash-size / DBGMCU (MAC-from-UID?) ==")
for v,l in [(0x1FFF7A10,"UID"),(0x1FFF7A22,"flashsize"),(0xE0042000,"DBGMCU"),(0x1FFF7A14,"UID+4")]:
    print(f"  {l} 0x{v:08x}: {sites(v)}")
print("\n== SLAC string neighborhoods ==")
for name,soff,sp in [("SLAC_INIT",0x0026c4,10),("PARA_REQ",0x002076,10),("MATCH_REQ",0x07eb8a,64),
 ("SET_KEY_REQ",0x001bc2,10),("PARA_CNF",0x002156,10),("BCB",0x003146,10)]:
    print(f"  {name:12s} f+0x{soff:06x}: {nb(soff,sp)}")
print()
disasm(0x000900,0xC0,"SDP start/init (security+transport defaults)")
