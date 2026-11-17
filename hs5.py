import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def imm16(h1,h2): return (((h1>>4)&0xF)<<12)|(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)

const=collections.defaultdict(list)
last={}
for a in range(0x400,n-4,2):
    h1=struct.unpack_from('<H',dec,a)[0]; h2=struct.unpack_from('<H',dec,a+2)[0]
    if (h1&0xFBF0)==0xF240: last[(h2>>8)&0xF]=(a,imm16(h1,h2))
    elif (h1&0xFBF0)==0xF2C0:
        rd=(h2>>8)&0xF
        if rd in last:
            pa,lo=last[rd]
            if a-pa<=12: const[(imm16(h1,h2)<<16)|lo].append(('mov',pa))
            del last[rd]
    if (h1&0xFF7F)==0xF85F:  # LDR literal T2
        u=(h1>>7)&1
        t=((a+4)&~3)+((h2&0xFFF) if u else -(h2&0xFFF))
        if 0<=t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldr2',a))
    if (h1&0xF800)==0x4800:  # LDR literal T1: 01001 Rt imm8
        t=((a+4)&~3)+(h1&0xFF)*4
        if t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldr1',a))
    if (h1&0xF800)==0xA000:  # ADR T1
        t=((a+4)&~3)+(h1&0xFF)*4
        if t<n: const[BASE+t].append(('adr1',a))
    if (h1&0xFBFF)==0xF20F:
        imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
        t=((a+4)&~3)+imm
        if t<n: const[BASE+t].append(('adr2+',a))
    elif (h1&0xFBFF)==0xF2AF:
        imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
        t=((a+4)&~3)-imm
        if 0<=t<n: const[BASE+t].append(('adr2-',a))
def sites(v):
    return ", ".join(f"{k}@f+0x{o:06x}" for k,o in const.get(v,[])[:12]) or "(none)"
def disasm(off,length,label=""):
    print(f"--- disasm f+0x{off:06x} {label} ---")
    for i in md.disasm(dec[off:off+length],BASE+off):
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:10s} {i.op_str}")
def hexdump(off,length):
    for a in range(off,off+length,16):
        row=dec[a:a+16]
        print(f"  f+0x{a:06x}: {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")

print("== sanity peripherals ==")
for v,l in [(0x40023800,"RCC"),(0x40006400,"CAN1"),(0x40013000,"SPI1")]:
    print(f"  {l}: {sites(v)}")
print("\n== ns / handshake strings ==")
for name,soff in {"ns_iso":0x014275,"ns_din":0x014292,"dbg_appProtoReq":0x0142ae,
 "dbg_ssReq_iso":0x014925,"dbg_ssReq_din":0x00d4f9,"dbg_schema1":0x0129a1,
 "dbg_schema2":0x012a36,"dbg_slac_match":0x07eb8a,"dbg_sdp_req":0x000dde}.items():
    print(f"  {name:16s}: {sites(BASE+soff)}")
print("\n== ports ==")
for v,l in [(15118,"15118"),(0x0E3B,"htons15118")]:
    print(f"  {l}: {sites(v)}")

print("\n== hex around RCC pool word f+0x0677e0..0x067810 ==")
hexdump(0x0677e0,0x30)
disasm(0x0677a0,0x60,"RCC init region")
print()
disasm(0x0141e0,0x60,"code before ns pool")
