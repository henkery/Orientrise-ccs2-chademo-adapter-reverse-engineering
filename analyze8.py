import sys, struct, re, collections

raw=open(sys.argv[1],'rb').read()
key=bytes([0x2b,0x23])
dec=bytes(b^key[i%2] for i,b in enumerate(raw))
open(sys.argv[2],'wb').write(dec)
print(f"decoded with [2b,23] -> {sys.argv[2]} ({len(dec)} bytes)")

print("\n== header [0:0x58] as text ==")
h=dec[:0x58]
print(repr(h))
print("hex:", h.hex(' '))

print("\n== histogram top8 ==")
c=collections.Counter(dec)
print([(hex(b),n) for b,n in c.most_common(8)])
for p in (0,1):
    cc=collections.Counter(dec[p::2])
    print(f"parity{p}: {[(hex(b),n) for b,n in cc.most_common(4)]}")

print("\n== strings >=8 (dedup, first 70) ==")
seen=set();out=[]
for m in re.finditer(rb'[\x20-\x7e]{8,}',dec):
    s=m.group()
    if s not in seen: seen.add(s);out.append((m.start(),s))
for off,s in out[:70]:
    print(f"0x{off:06x}: {s.decode()!r}")
print(f"total unique>=8: {len(out)}")

print("\n== window around 0xeb0 (connecting?) ==")
print(repr(dec[0xe90:0xf20]))

print("\n== code check [0x410:0x480] ==")
b=dec[0x410:0x480]
for i in range(0,len(b),16):
    row=b[i:i+16]
    print(f"{0x410+i:06x}: {' '.join(f'{x:02x}' for x in row)}")