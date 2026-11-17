import sys, collections, string

data = open(sys.argv[1],'rb').read()
hdr = data[:0x58]

PRINT = set(bytes(string.printable,'ascii')) - {0x0b,0x0c}

def score(b):
    return sum(1 for x in b if x in PRINT)/len(b)

# 1) single-byte XOR brute force on header
print("== single-byte XOR on header (top by printable score) ==")
res=[]
for k in range(256):
    d = bytes(x^k for x in hdr)
    res.append((score(d),k,d))
res.sort(reverse=True)
for s,k,d in res[:6]:
    print(f"key 0x{k:02x} score {s:.2f}: {d!r}")

# 2) known-plaintext: try candidate strings at every offset in header, derive key
cands = [b"MAIN_CCS2CHADEMO", b"CCS2CHADEMO", b"02.01.C009", b"ORIENT", b"orient",
         b"CHAdeMO", b"CHADEMO", b"CCS2", b"MAIN", b"V02", b"VER", b"FW", b"UPG",
         b"Orientrise", b"ORIENTRISE", b"02.01", b"C009", b"ADAPTER", b"adapter"]
print("\n== known-plaintext XOR key recovery (header) ==")
seen=set()
for c in cands:
    for off in range(0, len(hdr)-len(c)+1):
        key = bytes(hdr[off+i]^c[i] for i in range(len(c)))
        # check if key looks like a short repeating pattern
        for L in range(1,9):
            if len(key)>=L and all(key[i]==key[i%L] for i in range(len(key))):
                kk=key[:L]
                if kk not in seen:
                    seen.add(kk)
                    print(f"crib {c!r} @0x{off:02x} -> repeating key {kk!r} (L={L})")
                break

# 3) repeating-key XOR: for each L, per-column best single-byte key by printable score on header
print("\n== per-column single-byte best (header), candidate key lengths ==")
for L in range(1,17):
    key=bytearray()
    tot=0
    for col in range(L):
        colbytes = hdr[col::L]
        best=None
        for k in range(256):
            s=score(bytes(x^k for x in colbytes))
            if best is None or s>best[0]:
                best=(s,k)
        key.append(best[1]); tot+=best[0]*len(colbytes)
    d=bytes(hdr[i]^key[i%L] for i in range(len(hdr)))
    print(f"L={L:2d} key={bytes(key)!r} score={score(d):.2f} -> {d[:48]!r}")