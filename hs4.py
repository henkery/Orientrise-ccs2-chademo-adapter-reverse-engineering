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
    if (h1&0xFF7F)==0xF85F:
        u=(h1>>7)&1
        t=((a+4)&~3)+((h2&0xFFF) if u else -(h2&0xFFF))
        if 0<=t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldr',a))
    if (h1&0xF800)==0xA000:
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
    print(f"  --- disasm f+0x{off:06x} {label} ---")
    for i in md.disasm(dec[off:off+length],BASE+off):
        print(f"    0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:10s} {i.op_str}")

print("== sanity peripherals ==")
for v,l in [(0x40023800,"RCC"),(0x40006400,"CAN1"),(0x40013000,"SPI1")]:
    pat=struct.pack('<I',v); hits=[]; i=dec.find(pat)
    while i!=-1 and len(hits)<6: hits.append(i); i=dec.find(pat,i+1)
    print(f"  {l}: sites={sites(v)} | rawword="+(", ".join(f"f+0x{h:06x}" for h in hits) or "none"))

strs={"ns_iso":0x014275,"ns_din":0x014292,"dbg_appProtoReq":0x0142ae,
 "dbg_schema1":0x0129a1,"dbg_schema2":0x012a36,"dbg_ssReq_din":0x00d4f9,
 "dbg_ssReq_iso":0x014925,"dbg_slac_match":0x07eb8a,"dbg_mac":0x002646,
 "dbg_sdp_sendto":0x000dc6,"dbg_sdp_req":0x000dde}
print("\n== string xrefs ==")
xref_sites={}
for name,soff in strs.items():
    s=sites(BASE+soff); xref_sites[name]=const.get(BASE+soff,[])
    print(f"  {name:16s} f+0x{soff:06x}: {s}")

print("\n== ports ==")
for v,l in [(15118,"15118"),(0x0E3B,"htons15118"),(15119,"15119")]:
    print(f"  {l}: {sites(v)}")

# disassemble around first code xref of each namespace string
for name in ("ns_iso","ns_din","dbg_ssReq_iso","dbg_ssReq_din"):
    for k,o in xref_sites[name][:2]:
        start=max(0x400,o-0x40)
        disasm(start,0xA0,f"({name} via {k}@f+0x{o:06x})")
