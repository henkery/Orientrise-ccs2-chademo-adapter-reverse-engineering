import sys, struct, collections
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
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
    # LDR literal T2: 11111 U 001101 1111 -> hw1 & 0xFB7F == 0xF85F (clear U=bit10, bit7)
    if (h1&0xFB7F)==0xF85F:
        u=(h1>>10)&1
        t=((a+4)&~3)+((h2&0xFFF) if u else -(h2&0xFFF))
        if 0<=t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldr',a))
    # ADR T1: 10100 Rd imm8 -> target = Align(PC,4)+imm8*4
    if (h1&0xF800)==0xA000:
        t=((a+4)&~3)+(h1&0xFF)*4
        const[t].append(('adr1',a))
    # ADR T2 add/sub
    if (h1&0xFBFF)==0xF20F:
        imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
        const[((a+4)&~3)+imm].append(('adr2+',a))
    elif (h1&0xFBFF)==0xF2AF:
        imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
        const[((a+4)&~3)-imm].append(('adr2-',a))
def sites(v):
    return ", ".join(f"{k}@f+0x{o:06x}" for k,o in const.get(v,[])[:12]) or "(none)"

print("== sanity: peripheral literals ==")
for v,l in [(0x40023800,"RCC"),(0x40006400,"CAN1"),(0x40013000,"SPI1"),(0x40000000,"TIM2")]:
    print(f"  {l}: {sites(v)}")

strs={
 "ns_iso15118":0x014275,"ns_din70121":0x014292,"dbg_appProtoReq":0x0142ae,
 "dbg_schema1_DIN":0x0129a1,"dbg_schema2_ISO":0x012a36,
 "dbg_ssReq_din":0x00d4f9,"dbg_ssReq_iso":0x014925,
 "dbg_slac_match":0x07eb8a,"dbg_mac":0x002646,"dbg_mac_addr":0x02ebc6,
 "dbg_sdp_sendto":0x000dc6,"dbg_sdp_req":0x000dde,
 "rec_ns_iso":0x014272,"rec_ssReq_iso":0x01491e,
}
print("\n== string/record xrefs (fixed scanner) ==")
for name,soff in strs.items():
    print(f"  {name:18s} f+0x{soff:06x}: {sites(BASE+soff)}")

print("\n== ports ==")
for v,l in [(15118,"15118"),(0x0E3B,"htons15118"),(15119,"15119")]:
    print(f"  {l}: {sites(v)}")

print("\n== hex f+0x014900..0x014960 ==")
for a in range(0x014900,0x014960,16):
    row=dec[a:a+16]
    print(f"  f+0x{a:06x}: {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")
print("\n== hex f+0x00f020..0x00f070 ==")
for a in range(0x00f020,0x00f070,16):
    row=dec[a:a+16]
    print(f"  f+0x{a:06x}: {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")
