import sys, struct, collections
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
CHADEMO={0x100,0x101,0x102,0x103,0x104,0x105,0x108,0x109,0x110,0x111,0x112,
         0x200,0x201,0x202,0x301,0x700}

# 1) GB/T J1939 signature across ALL aligned words (plain or <<3|IDE)
print("== GB/T J1939 29-bit IDs (SA/PS=56/F4) in aligned words ==")
gb=[]
for off in range(0x400,n-3,4):
    v=struct.unpack_from('<I',dec,off)[0]
    for cand,enc in ((v,"plain"),(v>>3,"<<3") if v&4 else (None,None)):
        if cand is not None and (cand&0xFFFF) in (0xF456,0x56F4) and (cand>>26) in (4,6,7):
            pf=(cand>>16)&0xFF; pgn=(pf<<8) if pf<0xF0 else (pf<<8)|((cand>>8)&0xFF)
            gb.append((off,cand,enc,v,pf,pgn))
for off,cand,enc,v,pf,pgn in gb:
    print(f"  f+0x{off:06x} (0x{BASE+off:08x}) ID 0x{cand:08x} prio{cand>>26} PGN 0x{pgn:04x} SA 0x{cand&0xFF:02x} PS 0x{(cand>>8)&0xFF:02x} [{enc} word 0x{v:08x}]")
print("  total:",len(gb))

# 2) CHAdeMO ID clusters: words equal to a CHAdeMO ID, grouped within 64B
print("\n== CHAdeMO ID words (plain 32-bit) clustered within 64B ==")
hits=[off for off in range(0x400,n-3,4) if struct.unpack_from('<I',dec,off)[0] in CHADEMO]
clusters=[]; cur=[]
for off in hits:
    if cur and off-cur[-1]>64:
        clusters.append(cur); cur=[]
    cur.append(off)
if cur: clusters.append(cur)
for cl in clusters:
    if len(cl)<2: continue
    ids=[struct.unpack_from('<I',dec,o)[0] for o in cl]
    print(f"  0x{cl[0]:06x}-0x{cl[-1]:06x} ({len(cl)}): "+", ".join(f"0x{i:03x}" for i in ids))