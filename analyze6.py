import sys, collections, struct

raw=open(sys.argv[1],'rb').read()
dec=open(sys.argv[2],'rb').read()

# parity of zeros in decoded
ze=sum(1 for i in range(0,len(dec),2) if dec[i]==0)
zo=sum(1 for i in range(1,len(dec),2) if dec[i]==0)
print(f"decoded zeros: even={ze} odd={zo}")
# most common raw byte per parity
for p in (0,1):
    c=collections.Counter(raw[p::2])
    print(f"raw parity{p} top5: {[(hex(b),n) for b,n in c.most_common(5)]}")
for p in (0,1):
    c=collections.Counter(dec[p::2])
    print(f"dec parity{p} top5: {[(hex(b),n) for b,n in c.most_common(5)]}")

def dump(b,base=0):
    for i in range(0,len(b),16):
        row=b[i:i+16]
        hx=' '.join(f'{x:02x}' for x in row)
        asc=''.join(chr(x) if 32<=x<127 else '.' for x in row)
        print(f"{base+i:06x}: {hx:<48} {asc}")

print("\n== decoded [0x400:0x480] ==")
dump(dec[0x400:0x480],0x400)
print("\n== decoded [0xd00:0xd80] (string-like region) ==")
dump(dec[0xd00:0xd80],0xd00)

# crack header: 2-byte XOR, maximize printable over whole header
hdr=raw[:0x58]
PRINT=set(range(0x20,0x7f))|{0x0a,0x0d,0x09}
def sc(b): return sum(1 for x in b if x in PRINT)/len(b)
print("\n== header 2-byte XOR brute (top 12 by printable) ==")
res=[]
for k0 in range(256):
    for k1 in range(256):
        d=bytes(hdr[i]^(k0 if i%2==0 else k1) for i in range(len(hdr)))
        res.append((sc(d),k0,k1,d))
res.sort(reverse=True)
for s,k0,k1,d in res[:12]:
    print(f"[{k0:02x},{k1:02x}] {s:.2f}: {d!r}")