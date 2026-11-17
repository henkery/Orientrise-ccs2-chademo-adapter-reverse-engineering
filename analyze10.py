import sys, struct, collections, math

dec=open(sys.argv[1],'rb').read()
n=len(dec)
def ent(b):
    c=collections.Counter(b);N=len(b)
    return -sum(v/N*math.log2(v/N) for v in c.values())

print("== entropy per 512B (transitions) ==")
prev=None
for i in range(0,n,512):
    e=ent(dec[i:i+512])
    cls='LOW' if e<5.5 else ('MED' if e<6.9 else 'HIGH')
    if cls!=prev:
        print(f"0x{i:06x}: {cls} H={e:.2f}")
        prev=cls

print("\n== dump 0x58:0x98 and 0x380:0x420 ==")
for base in (0x58,0x380):
    b=dec[base:base+64]
    for i in range(0,len(b),16):
        row=b[i:i+16]
        print(f"{base+i:06x}: {' '.join(f'{x:02x}' for x in row)}  {''.join(chr(x) if 32<=x<127 else '.' for x in row)}")

print("\n== any RAM-range word (0x10000000-0x40000000, top byte 20/24/30) with odd-flash neighbors ==")
hits=[]
for off in range(0,n-16,4):
    sp=struct.unpack_from('<I',dec,off)[0]
    tb=sp>>24
    if tb in (0x20,0x24,0x30,0x10) and (sp&0xfff)==0 or (tb in (0x20,) and sp<0x20100000):
        w1=struct.unpack_from('<I',dec,off+4)[0]
        if w1&1 and 0x08000000<=w1<0x08100000:
            hits.append((off,sp,w1))
for off,sp,w1 in hits[:20]:
    print(f"off 0x{off:06x}: SP=0x{sp:08x} reset=0x{w1:08x}")
print(f"total {len(hits)}")

print("\n== runs of >=6 odd words in 0x08000000-0x08100000 (vector-table-like) ==")
run=0;start=0;found=[]
for off in range(0,n-4,4):
    w=struct.unpack_from('<I',dec,off)[0]
    if w&1 and 0x08000000<=w<0x08100000:
        if run==0: start=off
        run+=1
    else:
        if run>=6: found.append((start,run))
        run=0
if run>=6: found.append((start,run))
for s,r in found[:20]:
    sp=struct.unpack_from('<I',dec,s-4)[0] if s>=4 else 0
    print(f"off 0x{s:06x}: run={r} prevword=0x{sp:08x}")
print(f"total runs {len(found)}")