import sys, struct, re, collections

dec=open(sys.argv[1],'rb').read()
raw=open(sys.argv[2],'rb').read()
n=len(dec)

print("== search decoded for product/version strings ==")
for pat in [b"02.01", b"C009", b"CCS2", b"CHADEMO", b"CHAdeMO", b"MAIN_", b"ORIENT", b"Orient", b"orient", b"GD32", b"STM32", b"version", b"Version", b"VER"]:
    idxs=[m.start() for m in re.finditer(re.escape(pat), dec)]
    if idxs:
        print(f"{pat!r}: {[hex(i) for i in idxs[:8]]}")

print("\n== broad vector-table scan (SP in 0x200xxxxx, next word odd) ==")
hits=[]
for off in range(0,n-16,4):
    sp=struct.unpack_from('<I',dec,off)[0]
    if 0x20000000<=sp<0x20100000:
        w1=struct.unpack_from('<I',dec,off+4)[0]
        if w1&1 and w1<0x20000000:
            # count how many following words are odd flash-ish pointers
            cnt=0
            for k in range(1,8):
                w=struct.unpack_from('<I',dec,off+4*k)[0]
                if w&1 and w<0x20000000: cnt+=1
                else: break
            if cnt>=3:
                hits.append((off,sp,w1,cnt))
for off,sp,w1,cnt in hits[:16]:
    print(f"off 0x{off:06x}: SP=0x{sp:08x} v1=0x{w1:08x} run={cnt}")
print(f"total {len(hits)}")

print("\n== long strings >=10 (dedup, first 60) ==")
seen=set(); out=[]
for m in re.finditer(rb'[\x20-\x7e]{10,}', dec):
    s=m.group()
    if s not in seen:
        seen.add(s); out.append((m.start(),s))
for off,s in out[:60]:
    print(f"0x{off:06x}: {s.decode()!r}")
print(f"total unique >=10: {len(out)}")

print("\n== header known-plaintext: derive key from version/filename cribs ==")
hdr=raw[:0x58]
for crib in [b"02.01.C009", b"MAIN_CCS2CHADEMO_1", b"CCS2CHADEMO", b"MAIN_CCS2CHADEMO"]:
    for off in range(0,len(hdr)-len(crib)+1):
        key=bytes(hdr[off+i]^crib[i] for i in range(len(crib)))
        # does key match body key [2b,65] repeating at that offset?
        match=all(key[i]==bytes([0x2b,0x65])[(off+i)%2] for i in range(len(crib)))
        if match:
            print(f"crib {crib!r} @0x{off:02x} MATCHES body key [2b,65]")
        # or is key a clean 2-byte repeat?
        if len(key)>=4 and key[0]==key[2] and key[1]==key[3]:
            print(f"crib {crib!r} @0x{off:02x} -> 2-byte key {key[:2].hex(' ')}")