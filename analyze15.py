import sys, struct, collections, math, re
dec=open(sys.argv[1],'rb').read(); n=len(dec)
def ent(b):
    c=collections.Counter(b);N=len(b)
    return -sum(v/N*math.log2(v/N) for v in c.values())
def dump(base,ln):
    b=dec[base:base+ln]
    for i in range(0,len(b),16):
        row=b[i:i+16]
        print(f"{base+i:06x}: {' '.join(f'{x:02x}' for x in row)}  {''.join(chr(x) if 32<=x<127 else '.' for x in row)}")

pre=dec[0x58:0x400]
print(f"== prefix 0x58-0x400: {len(pre)} bytes, entropy={ent(pre):.3f} ==")
print("byte hist top8:", [(hex(b),c) for b,c in collections.Counter(pre).most_common(8)])
print("\n-- prefix as 32-bit LE words (first 40) --")
for i in range(0,160,4):
    print(f"0x{0x58+i:04x}: 0x{struct.unpack_from('<I',pre,i)[0]:08x}")
print("\n-- strings inside prefix --")
for m in re.finditer(rb'[\x20-\x7e]{4,}',pre):
    print(f"0x{0x58+m.start():04x}: {m.group()!r}")
print("\n-- prefix head dump --")
dump(0x58,64)
print("\n-- prefix tail (0x3c0-0x400) --")
dump(0x3c0,64)

print("\n== QCA version string context (0x2596) ==")
dump(0x2560,128)

print("\n== QCA / SPI / firmware-download related strings ==")
for p in [b"QCA",b"qca",b"SPI",b"spi",b"firmware",b"Firmware",b"FIRMWARE",b"FW_",b"fw_",b"download",b"Download",b"DOWNLOAD",b"boot",b"Boot",b"VS_SW",b"SW_VER",b"sw_ver",b"MAC-",b"MDIO",b"mdio",b"flash",b"Flash",b"FLASH",b"EEPROM",b"eeprom",b"image",b"Image",b"blob",b"load",b"Load"]:
    idxs=[m.start() for m in re.finditer(re.escape(p),dec)]
    if idxs:
        for i in idxs[:4]:
            ctx=dec[max(0,i-8):i+len(p)+20]
            ctx=''.join(chr(x) if 32<=x<127 else '.' for x in ctx)
            print(f"{p.decode():10s} @0x{i:06x}: {ctx!r}")

print("\n== low-entropy tail 0x8e800 structure (first 128B as words) ==")
for i in range(0,128,4):
    print(f"0x{0x8e800+i:06x}: 0x{struct.unpack_from('<I',dec,0x8e800+i)[0]:08x}")