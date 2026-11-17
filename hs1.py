import sys, struct, collections
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
def imm16(h1,h2): return (((h1>>4)&0xF)<<12)|(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)

# word index (2-aligned) for rodata pointer records
idx=collections.defaultdict(list)
for off in range(0x400,n-3,2):
    idx[struct.unpack_from('<I',dec,off)[0]].append(off)

# one-pass map: constant value -> code sites that materialize it
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

strs={
 "ns_iso15118":0x014275,
 "ns_din70121":0x014292,
 "dbg_appProtoReq":0x0142ae,
 "dbg_schema1_DIN":0x0129a1,
 "dbg_schema2_ISO":0x012a36,
 "dbg_sessionSetupReq_din":0x00d4f9,
 "dbg_sessionSetupReq_iso":0x014925,
 "dbg_slac_match_req":0x07eb8a,
 "dbg_mac_print":0x002646,
 "dbg_mac_addr":0x02ebc6,
 "dbg_sdp_sendto":0x000dc6,
 "dbg_sdp_req":0x000dde,
}
for name,soff in strs.items():
    S=BASE+soff
    print(f"\n=== {name}  f+0x{soff:06x} -> 0x{S:08x} ===")
    print("  direct code refs:", sites(S))
    for p in idx.get(S,[])[:8]:
        print(f"  ptr-record f+0x{p:06x}: refs to record:", sites(BASE+p))
        for d in (-4,-8,-12,-16,-20):
            r=sites(BASE+p+d)
            if r!="(none)": print(f"    record{d:+d}: {r}")

print("\n=== port/constants ===")
for v,label in [(15118,"15118 (SDP/V2GTP port)"),(0x0E3B,"htons(15118)"),(15119,"15119"),(0x3B0F,"0x3B0F")]:
    print(f"  {label}: {sites(v)}")

print("\n=== hex context around namespace strings f+0x014240..0x014330 ===")
for a in range(0x014240,0x014330,16):
    row=dec[a:a+16]
    print(f"  f+0x{a:06x}: {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")
