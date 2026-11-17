import sys, struct, re
dec=open(sys.argv[1],'rb').read(); n=len(dec)
print("== movw Rd,0x232b  (bytes 42 f2 2b 3X) = halfword XOR key ==")
hits=[]
for m in re.finditer(re.escape(b'\x42\xf2\x2b'),dec):
    i=m.start()
    if i+3<n and 0x30<=dec[i+3]<=0x3f:
        hits.append(i)
print("  movw 0x232b at:", [hex(i) for i in hits])

print("\n== movs 0x2b near movs 0x23 (byte-key decode setup), within 40B ==")
a=[m.start() for m in re.finditer(rb'[\x2b][\x20-\x27]',dec)]  # movs rX,#0x2b
b=set(m.start() for m in re.finditer(rb'[\x23][\x20-\x27]',dec)) # movs rY,#0x23
pairs=[]
for i in a:
    for j in range(i-40,i+40,2):
        if j in b and j!=i:
            pairs.append((i,j)); break
print("  candidate pairs:", [(hex(i),hex(j)) for i,j in pairs[:20]])

print("\n== eor-register loops (ldrb/strb post-inc + eor) candidate decode ==")
# ldrb rT,[rN],#1 = 0x7800|... ; look for eor (T1 0x4040-0x407f) density near file-read code
for i,j in pairs[:6]:
    lo=min(i,j)-24; hi=max(i,j)+40
    print(f"  --- around 0x{lo:06x}-0x{hi:06x} ---")
    b=dec[lo:hi]
    print("   "+b.hex(' '))

print("\n== context of movw 0x232b hits (disasm-ready) ==")
for i in hits[:6]:
    lo=i-32; hi=i+48
    print(f"  --- 0x{lo:06x} ---")
    print("   "+dec[lo:hi].hex(' '))