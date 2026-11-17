import sys, struct, collections, re
dec=open(sys.argv[1],'rb').read(); n=len(dec)
def dump(base,ln):
    b=dec[base:base+ln]
    for i in range(0,len(b),16):
        row=b[i:i+16]
        print(f"{base+i:06x}: {' '.join(f'{x:02x}' for x in row)}  {''.join(chr(x) if 32<=x<127 else '.' for x in row)}")

print("== tail 0x8e800 first 160B =="); dump(0x8e800,160)
print("\n== transition into tail 0x8e7c0-0x8e840 =="); dump(0x8e7c0,128)

print("\n== footer checksum hypotheses (target 0x2dbe / 0x10c0) ==")
def crc16(data,poly,init,refin,refout,xorout):
    def rev(x,w):
        r=0
        for _ in range(w): r=(r<<1)|(x&1); x>>=1
        return r
    crc=init
    for b in data:
        if refin: b=rev(b,8)
        crc^=b<<8
        for _ in range(8):
            crc=((crc<<1)^poly)&0xffff if crc&0x8000 else (crc<<1)&0xffff
    if refout: crc=rev(crc,16)
    return crc^xorout
regions={"cipher(0x58-0x3ea)":dec[0x58:0x3ea],"whole":dec,"app(0x400-)":dec[0x400:],"prefix(0x58-0x400)":dec[0x58:0x400]}
variants={"CCITT-FALSE":(0x1021,0xffff,False,False,0),"XMODEM":(0x1021,0,False,False,0),
          "ARC/IBM":(0x8005,0,True,True,0),"MODBUS":(0x8005,0xffff,True,True,0),
          "CCITT-0x1D0F":(0x1021,0x1d0f,False,False,0)}
for rn,rd in regions.items():
    hits=[]
    for vn,(p,i,ri,ro,xo) in variants.items():
        c=crc16(rd,p,i,ri,ro,xo)
        if c in (0x2dbe,0x10c0): hits.append(f"{vn}=0x{c:04x}")
    print(f"{rn}: {hits if hits else 'no crc16 match'}")

print("\n== QCA firmware-download / PIB / NVM / vendor strings ==")
for p in [b"PIB",b"pib",b"NVM",b"nvm",b"VS_",b"vs_",b"7005",b"INT",b"intellon",b"Intellon",b"AMP",b"amp",b"boot",b"Boot",b"BOOT",b"MAC-",b"MDIO",b"mdio",b"SW_VER",b"sw_ver",b"VER_REQ",b"ver_req",b"firmware",b"Firmware",b"FIRMWARE",b"download",b"Download",b"upgrade",b"Upgrade",b"image",b"Image",b"blob",b"load",b"Load",b"flash",b"Flash",b"FLASH",b"eeprom",b"EEPROM"]:
    idxs=[m.start() for m in re.finditer(re.escape(p),dec)]
    if idxs:
        for i in idxs[:3]:
            ctx=dec[max(0,i-6):i+len(p)+22]
            ctx=''.join(chr(x) if 32<=x<127 else '.' for x in ctx)
            print(f"{p.decode():10s} @0x{i:06x}: {ctx!r}")