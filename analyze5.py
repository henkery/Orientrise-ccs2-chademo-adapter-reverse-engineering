import sys, numpy as np, collections, struct, re

raw = open(sys.argv[1],'rb').read()
key = bytes([0x2b,0x65])
dec = bytes(b ^ key[i%2] for i,b in enumerate(raw))
open(sys.argv[2],'wb').write(dec)
print(f"decoded {len(dec)} bytes -> {sys.argv[2]}")

print("\n== decoded byte histogram (top8) ==")
c=collections.Counter(dec)
print([(hex(b),cnt) for b,cnt in c.most_common(8)])

def dump(b,base=0):
    for i in range(0,len(b),16):
        row=b[i:i+16]
        hx=' '.join(f'{x:02x}' for x in row)
        asc=''.join(chr(x) if 32<=x<127 else '.' for x in row)
        print(f"{base+i:06x}: {hx:<48} {asc}")

print("\n== decoded header [0:0x60] ==")
dump(dec[:0x60])

print("\n== decoded [0x58:0xc0] (possible code/vector start) ==")
dump(dec[0x58:0xc0],0x58)

# search for Cortex-M vector table: word in RAM range then odd (Thumb) flash pointers
print("\n== scan for vector-table-like pattern (SP in 0x200xxxxx, next ptr odd & in flash) ==")
hits=[]
for off in range(0, len(dec)-8, 4):
    sp,rv = struct.unpack_from('<II', dec, off)
    if (0x20000000 <= sp < 0x20100000) and (rv & 1) and (0x08000000 <= rv < 0x08100000 or 0x00000000 <= rv < 0x00100000):
        hits.append((off,sp,rv))
for off,sp,rv in hits[:12]:
    print(f"off 0x{off:06x}: SP=0x{sp:08x} reset=0x{rv:08x}")
print(f"total hits: {len(hits)}")

# printable strings
print("\n== printable strings >=6 (first 40) ==")
strs=re.findall(rb'[\x20-\x7e]{6,}', dec)
for s in strs[:40]:
    off=dec.find(s)
    print(f"0x{off:06x}: {s.decode()!r}")
print(f"total strings>=6: {len(strs)}")