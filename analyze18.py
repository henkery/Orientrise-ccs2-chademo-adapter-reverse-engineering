import sys, struct
dec=open(sys.argv[1],'rb').read(); n=len(dec)
LO,HI=0x08020000,0x08100000
# The pointer table stores 32-bit LE flash addresses at (offset%4==2) alignment.
# Hypothesis: file offset 0x400 (app code start) links at 0x08020000 => B0=0x0801FC00.
B0=0x0801FC00
def resolve(p): return p-B0   # target file offset

print("== find start of pointer-table region (scan 0x8c000..end, align%4==2) ==")
first=None; cnt=0
for off in range(0x8c000,n-3):
    if off%4!=2: continue
    v=struct.unpack_from('<I',dec,off)[0]
    if LO<=v<HI:
        if first is None: first=off
        cnt+=1
print(f"first flash-pointer at 0x{first:06x}, total {cnt} pointers in region")

print("\n== sample records + resolved targets (B0=0x%08x) ==" % B0)
def isstr(b):
    return len(b)>=3 and all(32<=x<127 or x in (0,10,13) for x in b)
shown=0
for off in range(first, min(first+400,n-3)):
    if off%4!=2: continue
    v=struct.unpack_from('<I',dec,off)[0]
    if LO<=v<HI:
        t=resolve(v)
        tag=""
        if 0<=t<n:
            tgt=dec[t:t+24]
            if isstr(tgt.split(b'\x00')[0]) and len(tgt.split(b'\x00')[0])>=3:
                tag="STR "+repr(tgt.split(b'\x00')[0].decode())
            else:
                tag="bytes "+tgt[:8].hex(' ')
        print(f"  [0x{off:06x}] ptr=0x{v:08x} -> file 0x{t:06x}  {tag}")
        shown+=1
    else:
        if v<0x1000: print(f"  [0x{off:06x}] int={v}")
    if shown>40: break

print("\n== verify base: do word1-style ptrs (0x080affXX) land on strings? ==")
ok=0;tot=0
for off in range(first,n-3):
    if off%4!=2: continue
    v=struct.unpack_from('<I',dec,off)[0]
    if 0x080a0000<=v<0x080c0000:
        t=resolve(v); tot+=1
        if 0<=t<n:
            s=dec[t:t+32].split(b'\x00')[0]
            if isstr(s) and len(s)>=3: ok+=1
print(f"0x080a/bXXXX ptrs resolving to printable strings: {ok}/{tot}")

print("\n== alternative bases: string-resolution score ==")
for cand in (0x08000000,0x0801FC00,0x08020000,0x0801F000,0x08010000):
    ok=0;tot=0
    for off in range(first,n-3):
        if off%4!=2: continue
        v=struct.unpack_from('<I',dec,off)[0]
        if 0x080a0000<=v<0x080c0000:
            t=v-cand; tot+=1
            if 0<=t<n:
                s=dec[t:t+32].split(b'\x00')[0]
                if isstr(s) and len(s)>=3: ok+=1
    print(f"  B0=0x{cand:08x} (file0x400->0x{cand+0x400:08x}): {ok}/{tot} strings")