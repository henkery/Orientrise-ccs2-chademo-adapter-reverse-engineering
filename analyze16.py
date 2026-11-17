import sys, struct, collections, math
dec=open(sys.argv[1],'rb').read(); n=len(dec)
pre=dec[0x58:0x400]

print("== prefix: repeated 16-byte blocks (AES-ECB tell) ==")
blocks=collections.Counter(pre[i:i+16] for i in range(0,len(pre)-15,16))
rep=[(b.hex(),c) for b,c in blocks.items() if c>1]
print("repeated 16B blocks:", rep if rep else "NONE")
print("== prefix: repeated 4-byte words ==")
w=collections.Counter(struct.unpack_from('<I',pre,i)[0] for i in range(0,len(pre)-3,4))
print("top repeated words:", [(hex(x),c) for x,c in w.most_common(5)])

print("\n== prefix autocorr shifts 1..64 (XOR-key tell) ==")
ac=[]
for s in range(1,65):
    m=sum(1 for i in range(len(pre)-s) if pre[i]==pre[i+s])/(len(pre)-s)
    ac.append((m,s))
ac.sort(reverse=True)
print("top:", [(f'{m:.3f}',s) for m,s in ac[:8]])

print("\n== prefix length / footer alignment ==")
print(f"len={len(pre)} (0x{len(pre):x}); len%16={len(pre)%16}, len%8={len(pre)%8}")
for foot in (8,16,22,24,32):
    print(f"  if footer={foot}B: cipher={len(pre)-foot}B, %16={(len(pre)-foot)%16}, %8={(len(pre)-foot)%8}")
print("footer bytes 0x3e0-0x400:", dec[0x3e0:0x400].hex(' '))

print("\n== scan for large contiguous HIGH-entropy regions (potential embedded blob) ==")
def ent(b):
    c=collections.Counter(b);N=len(b)
    return -sum(v/N*math.log2(v/N) for v in c.values())
BS=1024; run=None
for i in range(0,n,BS):
    e=ent(dec[i:i+BS])
    if e>7.2:
        if run is None: run=[i,i+BS]
        else: run[1]=i+BS
    else:
        if run and run[1]-run[0]>=2048:
            print(f"HIGH-entropy region 0x{run[0]:06x}-0x{run[1]:06x} ({run[1]-run[0]}B)")
        run=None
if run and run[1]-run[0]>=2048:
    print(f"HIGH-entropy region 0x{run[0]:06x}-0x{run[1]:06x} ({run[1]-run[0]}B)")

print("\n== SPI1 / QCA code references (peripheral literal locations) ==")
for target,name in [(0x40013000,"SPI1"),(0x40006400,"CAN1"),(0x40006800,"CAN2")]:
    tb=struct.pack('<I',target)
    idxs=[]; st=0
    while True:
        i=dec.find(tb,st)
        if i<0: break
        idxs.append(i); st=i+1
    print(f"{name} 0x{target:08x} literal at: {[hex(i) for i in idxs]}")

print("\n== tail 0x8e800: interpret as 16-bit pairs, histogram of first u16 ==")
c=collections.Counter(struct.unpack_from('<H',dec,0x8e800+i)[0] for i in range(0,0x2cc4,2))
print("top u16:", [(hex(x),cnt) for x,cnt in c.most_common(8)])