import sys, numpy as np, collections

data = np.frombuffer(open(sys.argv[1],'rb').read(), dtype=np.uint8)
n = len(data)
print(f"size {n} 0x{n:x}")

def autocorr(buf, shifts):
    out=[]
    for s in shifts:
        if s>=len(buf): continue
        m = np.mean(buf[:-s]==buf[s:])
        out.append((float(m),s))
    out.sort(reverse=True)
    return out

print("\n== full-file autocorr, shifts 1..512 (top 30) ==")
for m,s in autocorr(data, range(1,513))[:30]:
    print(f"shift {s:4d} 0x{s:03x}: {m:.4f}")

# locate low-entropy tail precisely: entropy per 256B in last 64KB
print("\n== entropy per 256B, last 40KB (find table start) ==")
def ent(b):
    c=collections.Counter(b.tobytes()); N=len(b)
    return -sum(v/N*np.log2(v/N) for v in c.values())
start=n-40960
prev=None
for i in range(start,n,256):
    e=ent(data[i:i+256])
    cls='LOW' if e<5.5 else ('MED' if e<6.8 else 'HIGH')
    if cls!=prev:
        print(f"0x{i:06x}: {cls} H={e:.2f}")
        prev=cls

# tail region analysis: assume last ~6KB is the table
tail = data[n-6144:]
print("\n== tail byte histogram by position mod 4 (top2 each) ==")
for p in range(4):
    c=collections.Counter(tail[p::4].tobytes())
    print(f"pos{p}: {[(hex(b),cnt) for b,cnt in c.most_common(3)]}")
print("\n== tail byte histogram by position mod 8 (top2 each) ==")
for p in range(8):
    c=collections.Counter(tail[p::8].tobytes())
    print(f"pos{p}: {[(hex(b),cnt) for b,cnt in c.most_common(2)]}")

print("\n== tail autocorr shifts 1..64 (top 16) ==")
for m,s in autocorr(tail, range(1,65))[:16]:
    print(f"shift {s:3d}: {m:.4f}")

# header two-cluster check
hdr=data[:0x58]
print("\n== header value distribution ==")
lo=(hdr<0x40).sum(); hi=(hdr>=0x40).sum()
print(f"<0x40: {lo}, >=0x40: {hi}")
print("high bytes:", [hex(x) for x in hdr if x>=0x40])