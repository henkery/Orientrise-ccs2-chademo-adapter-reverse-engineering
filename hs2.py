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
for a in range(0x400,n-4,2):
    h1=struct.unpack_from('<H',dec,a)[0]
    if (h1&0xFF7F)!=0xF85F: continue
    h2=struct.unpack_from('<H',dec,a+2)[0]
    t=((a+4)&~3)+((h2&0xFFF) if (h1>>7)&1 else -(h2&0xFFF))
    if 0<=t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldr',a))
def sites(v):
    return ", ".join(f"{k}@f+0x{o:06x}" for k,o in const.get(v,[])[:10]) or "(none)"

print("== sanity: peripheral literals ==")
for v,l in [(0x40023800,"RCC"),(0x40006400,"CAN1"),(0x40013000,"SPI1"),(0x40000000,"TIM2")]:
    print(f"  {l}: {sites(v)}")

targets={
 "ns_iso":0x014275,"ns_din":0x014292,"dbg_appProtoReq":0x0142ae,
 "dbg_schema1":0x0129a1,"dbg_schema2":0x012a36,
 "dbg_ssReq_din":0x00d4f9,"dbg_ssReq_iso":0x014925,
 "dbg_slac_match":0x07eb8a,"dbg_mac":0x002646,
 "dbg_sdp_sendto":0x000dc6,"ram_ptr_before_ns":None,
}
print("\n== raw 4-byte LE search, ANY alignment ==")
for name,soff in targets.items():
    v=0x20003198 if soff is None else BASE+soff
    pat=struct.pack('<I',v)
    hits=[]; i=dec.find(pat)
    while i!=-1 and len(hits)<12:
        hits.append(i); i=dec.find(pat,i+1)
    print(f"  {name} (0x{v:08x}): "+(", ".join(f"f+0x{h:06x}{'(odd)' if h&1 else ''}" for h in hits) or "(none)"))

print("\n== ADR/ADD-pc scan for ns strings ==")
for soff in (0x014275,0x014292):
    S=BASE+soff; hits=[]
    for a in range(0x400,n-4,2):
        h1=struct.unpack_from('<H',dec,a)[0]; h2=struct.unpack_from('<H',dec,a+2)[0]
        if (h1&0xFBFF)==0xF20F:  # ADR add
            imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
            if ((a+4)&~3)+imm==S: hits.append(('adr+',a))
        elif (h1&0xFBFF)==0xF2AF:  # ADR sub
            imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
            if ((a+4)&~3)-imm==S: hits.append(('adr-',a))
    print(f"  f+0x{soff:06x}: "+(", ".join(f"{k}@f+0x{o:06x}" for k,o in hits[:10]) or "(none)"))

print("\n== port words in rodata (any 2-aligned) ==")
idx=collections.defaultdict(list)
for off in range(0x400,n-3,2):
    idx[struct.unpack_from('<I',dec,off)[0]].append(off)
for v in (15118,0x0E3B,15119,0x0F3B,0x3B0E):
    hs=idx.get(v,[])
    print(f"  0x{v:08x}: "+(", ".join(f"f+0x{h:06x}" for h in hs[:12]) or "(none)"))
# halfword search for port BE/LE
for pat,l in [(struct.pack('>H',15118),"BE15118"),(struct.pack('<H',15118),"LE15118")]:
    hits=[]; i=dec.find(pat)
    while i!=-1 and len(hits)<15: hits.append(i); i=dec.find(pat,i+1)
    print(f"  {l}: "+", ".join(f"f+0x{h:06x}" for h in hits))

print("\n== wider hex context f+0x0141e0..0x0142b0 ==")
for a in range(0x0141e0,0x0142b0,16):
    row=dec[a:a+16]
    print(f"  f+0x{a:06x}: {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")
