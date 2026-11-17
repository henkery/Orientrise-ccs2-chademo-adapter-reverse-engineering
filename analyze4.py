import sys, numpy as np, collections, string

raw = open(sys.argv[1],'rb').read()
data = np.frombuffer(raw, dtype=np.uint8)
n=len(data)
PRINT=set(bytes(string.printable,'ascii'))-{0x0b,0x0c}
def pscore(b): return sum(1 for x in b if x in PRINT)/max(1,len(b))

# autocorr table shifts 1..128
ac={}
for s in range(1,129):
    ac[s]=float(np.mean(data[:-s]==data[s:]))

print("== key-length detection: mean autocorr(multiples of L) / mean(non-multiples) ==")
best=[]
for L in range(1,65):
    mult=[ac[s] for s in range(1,129) if s%L==0]
    non =[ac[s] for s in range(1,129) if s%L!=0]
    if mult and non:
        ratio=np.mean(mult)/np.mean(non)
        best.append((ratio,L,np.mean(mult),np.mean(non)))
best.sort(reverse=True)
for r,L,m,nm in best[:12]:
    print(f"L={L:2d}: ratio={r:.2f} mult={m:.4f} non={nm:.4f}")

print("\n== overall most common bytes ==")
c=collections.Counter(raw)
print([(hex(b),cnt) for b,cnt in c.most_common(8)])

hdr=raw[:0x58]
print("\n== key recovery: assume most-common cipher byte per column == plain 0x00 or 0xFF ==")
for L in [1,2,4,8,16,32]:
    for pad in (0x00,0xff):
        key=bytearray()
        for col in range(L):
            cb=collections.Counter(raw[col::L])
            key.append(cb.most_common(1)[0][0]^pad)
        d=bytes(hdr[i]^key[i%L] for i in range(len(hdr)))
        print(f"L={L:2d} pad={pad:02x} key={bytes(key).hex(' ')} hdr_score={pscore(d):.2f} hdr={d[:40]!r}")

print("\n== cumulative XOR (plaintext-feedback) header, try p0 guesses ==")
cum=[]
acc=0
for b in hdr:
    acc^=b; cum.append(acc)
# decoded p[i] = cum[i] ^ p0 ; try p0 to maximize printable
res=[]
for p0 in range(256):
    d=bytes(x^p0 for x in cum)
    res.append((pscore(d),p0,d))
res.sort(reverse=True)
for s,p0,d in res[:4]:
    print(f"p0=0x{p0:02x} score={s:.2f}: {d!r}")