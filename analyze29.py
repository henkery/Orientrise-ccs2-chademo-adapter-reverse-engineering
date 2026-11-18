import sys, struct, collections
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000

def imm16(hw1,hw2):
    return (((hw1>>4)&0xF)<<12)|(((hw1>>10)&1)<<11)|(((hw2>>12)&7)<<8)|(hw2&0xFF)
def ror32(v,r):
    r&=31; return ((v>>r)|(v<<(32-r)))&0xFFFFFFFF if r else v
def thumb_expand_imm(c):
    if (c>>10)==0:
        b=c&0xFF; op=(c>>8)&3
        return [b,(b<<16)|b,(b<<24)|(b<<8),(b<<24)|(b<<16)|(b<<8)|(b)][op]&0xFFFFFFFF
    return ror32(0x80|(c&0x7F),(c>>7)&0x1F)

movimm=collections.defaultdict(list)   # MOV/MOVS immediate (ThumbExpandImm)
movw=collections.defaultdict(list)
const32=collections.defaultdict(list)
lastmovw={}
for a in range(0x400,n-4,2):
    hw1=struct.unpack_from('<H',dec,a)[0]; hw2=struct.unpack_from('<H',dec,a+2)[0]
    if (hw1&0xFBFF)==0xF04F:            # MOV/MOVS imm T2
        i=(hw1>>10)&1; imm3=(hw2>>12)&7; imm8=hw2&0xFF
        movimm[thumb_expand_imm((i<<11)|(imm3<<8)|imm8)].append(a)
    if (hw1&0xFBF0)==0xF240:
        Rd=(hw2>>8)&0xF; v=imm16(hw1,hw2); movw[v].append(a); lastmovw[Rd]=(a,v)
    elif (hw1&0xFBF0)==0xF2C0:
        Rd=(hw2>>8)&0xF
        if Rd in lastmovw:
            pa,lo=lastmovw[Rd]
            if a-pa<=12: const32[(imm16(hw1,hw2)<<16)|lo].append(pa)
            del lastmovw[Rd]

pool=collections.defaultdict(list)
for a in range(0x400,n-4,2):
    hw1=struct.unpack_from('<H',dec,a)[0]
    if (hw1&0xFF7F)!=0xF85F: continue
    hw2=struct.unpack_from('<H',dec,a+2)[0]
    t=((a+4)&~3)+((hw2&0xFFF) if (hw1>>7)&1 else -(hw2&0xFFF))
    if 0<=t<n-3: pool[struct.unpack_from('<I',dec,t)[0]].append(t)

CHADEMO={0x100,0x101,0x102,0x103,0x104,0x105,0x108,0x109,0x110,0x111,0x112,
         0x200,0x201,0x202,0x301,0x700}
def gb_sig(v): return (v&0xFFFF) in (0xF456,0x56F4) and (v>>26) in (4,6,7)
def fmt(o): return ", ".join(f"0x{x:06x}" for x in sorted(set(o))[:10])

print("== MOV-immediate == CHAdeMO ID (plain) ==")
for sid in sorted(CHADEMO):
    if sid in movimm: print(f"  0x{sid:03x}  @ {fmt(movimm[sid])}")
print("\n== MOVW == CHAdeMO ID ==")
for sid in sorted(CHADEMO):
    if sid in movw: print(f"  0x{sid:03x}  @ {fmt(movw[sid])}")
print("\n== 32-bit (mov/pool) == CHAdeMO id<<21 (+flags) ==")
for sid in sorted(CHADEMO):
    for tag,src in (("mov",const32),("pool",pool)):
        for fv in range(sid<<21,(sid<<21)+8):
            if fv in src: print(f"  0x{sid:03x} {tag} 0x{fv:08x} @ {fmt(src[fv])}")
print("\n== GB/T J1939 (SA/PS=56/F4) in any immediate/pool ==")
found=set()
for src,tag in ((movimm,"movimm"),(movw,"movw"),(const32,"mov"),(pool,"pool")):
    for v,offs in src.items():
        for cand in (v, v>>3 if v&4 else None):
            if cand is not None and gb_sig(cand) and cand not in found:
                found.add(cand)
                pf=(cand>>16)&0xFF; pgn=(pf<<8) if pf<0xF0 else (pf<<8)|((cand>>8)&0xFF)
                print(f"  ID 0x{cand:08x} prio{cand>>26} PGN 0x{pgn:04x} SA 0x{cand&0xFF:02x} PS 0x{(cand>>8)&0xFF:02x} {tag} 0x{v:08x} @ {fmt(offs)}")