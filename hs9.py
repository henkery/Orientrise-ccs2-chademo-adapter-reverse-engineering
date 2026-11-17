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
def sites(v): return ", ".join(f"{k}@f+0x{o:06x}" for k,o in const.get(v,[])[:12]) or "(none)"
def disasm(off,length,label=""):
    print(f"--- disasm f+0x{off:06x}..+0x{length:x} {label} ---")
    for i in md.disasm(dec[off:off+length],BASE+off):
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:10s} {i.op_str}")

disasm(0x0690ae,0x90,"get_evccid/mac source (called by ISO SessionSetup)")
print("\n== SDP / SLAC / MAC string xrefs ==")
for name,soff in {"dbg_sdp_req":0x000dde,"dbg_sdp_sendto":0x000dc6,"dbg_sdp_start":0x000d4a,
 "dbg_slac_match":0x07eb8a,"dbg_mac":0x002646,"dbg_mac_addr":0x02ebc6,"dbg_mac2":0x02f9b6,
 "dbg_no_tls":0x000d66,"dbg_pnc_no_tls":0x0104ea}.items():
    print(f"  {name:16s} f+0x{soff:06x}: {sites(BASE+soff)}")
print("\n== port 15118 / 0x3b0e / htons ==")
for v in (15118,0x3b0e,0x0e3b,15119,0x3b0f):
    print(f"  0x{v:x}: {sites(v)}")
