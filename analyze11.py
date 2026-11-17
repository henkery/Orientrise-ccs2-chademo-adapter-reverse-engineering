import sys, struct, collections

dec=open(sys.argv[1],'rb').read()
n=len(dec)
def dump(base,ln=64):
    b=dec[base:base+ln]
    for i in range(0,len(b),16):
        row=b[i:i+16]
        print(f"{base+i:06x}: {' '.join(f'{x:02x}' for x in row)}  {''.join(chr(x) if 32<=x<127 else '.' for x in row)}")

print("== transition 0x3f0:0x450 ==")
dump(0x3f0,96)

print("\n== runs of >=8 odd words <0x20000000 (any flash base) ==")
run=0;start=0;found=[]
for off in range(0,n-4,4):
    w=struct.unpack_from('<I',dec,off)[0]
    if w&1 and 0x10000<w<0x20000000:
        if run==0:start=off
        run+=1
    else:
        if run>=8:found.append((start,run))
        run=0
if run>=8:found.append((start,run))
for s,r in found[:25]:
    prev=struct.unpack_from('<I',dec,s-4)[0] if s>=4 else 0
    print(f"off 0x{s:06x}: run={r} prev=0x{prev:08x} first=0x{struct.unpack_from('<I',dec,s)[0]:08x}")
print(f"total {len(found)}")

print("\n== low-entropy tail 0x8e800 ==")
dump(0x8e800,64)
print("\n== very end 0x91440 ==")
dump(0x91440,0x84)
print("\n== high-entropy 0x8c400 ==")
dump(0x8c400,48)

print("\n== flash-range word histogram (top bases) ==")
c=collections.Counter()
for off in range(0,n-4,4):
    w=struct.unpack_from('<I',dec,off)[0]
    if 0x08000000<=w<0x08100000:
        c[w>>12]+=1
print("top 4KB pages:", [(hex(k<<12),v) for k,v in c.most_common(10)])