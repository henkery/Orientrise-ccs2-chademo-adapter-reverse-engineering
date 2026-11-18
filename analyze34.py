import sys, struct, collections
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
def imm16(h1,h2): return (((h1>>4)&0xF)<<12)|(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)

# index words->offsets (2-aligned) for xref chasing
idx=collections.defaultdict(list)
for off in range(0x400,n-3,2):
    idx[struct.unpack_from('<I',dec,off)[0]].append(off)

def code_xrefs(target):
    """find code offsets that load `target` via movw/movt or ldr-literal pool"""
    out=[]
    # movw/movt building target
    last={}
    for a in range(0x400,n-4,2):
        h1=struct.unpack_from('<H',dec,a)[0]; h2=struct.unpack_from('<H',dec,a+2)[0]
        if (h1&0xFBF0)==0xF240: last[(h2>>8)&0xF]=(a,imm16(h1,h2))
        elif (h1&0xFBF0)==0xF2C0:
            rd=(h2>>8)&0xF
            if rd in last:
                pa,lo=last[rd]
                if a-pa<=12 and ((imm16(h1,h2)<<16)|lo)==target: out.append(pa)
                del last[rd]
    # ldr-literal whose pool word == target
    for a in range(0x400,n-4,2):
        h1=struct.unpack_from('<H',dec,a)[0]
        if (h1&0xFF7F)!=0xF85F: continue
        h2=struct.unpack_from('<H',dec,a+2)[0]
        t=((a+4)&~3)+((h2&0xFFF) if (h1>>7)&1 else -(h2&0xFFF))
        if 0<=t<n-3 and struct.unpack_from('<I',dec,t)[0]==target: out.append(a)
    return out

# timing/config strings to trace (file offsets from strings.txt)
strs={
 "CAN_6s_timeout":0x08753e,
 "H100_1s_timeout":0x022c3a,
 "GB/T_BRM_5s":0x01eaba,
 "CANBAUD1":0x02ec2e,
}
for name,soff in strs.items():
    S=BASE+soff
    print(f"\n=== {name}  str f+0x{soff:06x} -> 0x{S:08x} ===")
    prefs=idx.get(S,[])
    print("  pointer refs:", ", ".join(f"0x{p:06x}" for p in prefs[:6]))
    for p in prefs[:3]:
        R=BASE+p   # record address (str_ptr field)
        cx=code_xrefs(R)
        # also try record starting a few words earlier
        print(f"   record@0x{p:06x} (0x{R:08x}) code-xrefs:", ", ".join(f"0x{c:06x}" for c in cx[:6]))

# SysTick at any alignment
print("\n== SysTick regs (0xE000E010/14/18) any 2B alignment ==")
for off in range(0x400,n-3,2):
    w=struct.unpack_from('<I',dec,off)[0]
    if w in (0xE000E010,0xE000E014,0xE000E018):
        print(f"  f+0x{off:06x} = 0x{w:08x}")