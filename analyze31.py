import sys, struct, collections
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
CHADEMO={0x100,0x101,0x102,0x103,0x104,0x105,0x108,0x109,0x110,0x111,0x112,
         0x200,0x201,0x202,0x301,0x700}

# GB/T: low halfword of a J1939 ID is 0xF456 (chg->BMS) or 0x56F4 (BMS->chg)
print("== GB/T J1939 low-half signature (u16 == F456/56F4) ==")
cnt=0
for off in range(0x400,n-1,2):
    lo=struct.unpack_from('<H',dec,off)[0]
    if lo in (0xF456,0x56F4):
        hi=struct.unpack_from('<H',dec,off+2)[0] if off+3<n else 0
        cand=(hi<<16)|lo
        if (cand>>26) in (4,6,7):
            pf=(cand>>16)&0xFF; pgn=(pf<<8) if pf<0xF0 else (pf<<8)|((cand>>8)&0xFF)
            print(f"  f+0x{off:06x} ID 0x{cand:08x} prio{cand>>26} PGN 0x{pgn:04x} SA 0x{cand&0xFF:02x} PS 0x{(cand>>8)&0xFF:02x}")
            cnt+=1
print("  total:",cnt)

# CHAdeMO u16 clusters within 32 bytes
print("\n== CHAdeMO ID halfwords (u16) clustered within 32B ==")
hits=[off for off in range(0x400,n-1,2) if struct.unpack_from('<H',dec,off)[0] in CHADEMO]
clusters=[]; cur=[]
for off in hits:
    if cur and off-cur[-1]>32: clusters.append(cur); cur=[]
    cur.append(off)
if cur: clusters.append(cur)
for cl in clusters:
    if len(cl)<3: continue
    ids=[struct.unpack_from('<H',dec,o)[0] for o in cl]
    print(f"  0x{cl[0]:06x}-0x{cl[-1]:06x} ({len(cl)}): "+", ".join(f"0x{i:03x}" for i in ids))