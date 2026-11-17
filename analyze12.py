import sys, struct, collections, re
dec=open(sys.argv[1],'rb').read(); n=len(dec)

print("== peripheral-range words (0x40000000-0x60000000) top values ==")
c=collections.Counter()
loc={}
for off in range(0,n-4,4):
    w=struct.unpack_from('<I',dec,off)[0]
    if 0x40000000<=w<0x60000000:
        c[w]+=1; loc.setdefault(w,off)
for w,cnt in c.most_common(25):
    print(f"0x{w:08x} x{cnt:3d} first@0x{loc[w]:06x}")

print("\n== any plausible initial SP (word & 0xFF000000 in RAM ranges, low bytes small) ==")
for off in range(0,n-4,4):
    w=struct.unpack_from('<I',dec,off)[0]
    if (w>>24) in (0x20,0x24,0x30,0x10,0x60) and (w&0xffff)<0x8000 and (w&0xffff)>0x100:
        print(f"off 0x{off:06x}: 0x{w:08x}")

print("\n== more identifying strings ==")
for p in [b"FreeRTOS",b"freertos",b"RT-Thread",b"rtthread",b"ThreadX",b"uC/OS",b"lwIP",b"lwip",b"uIP",b"STM32",b"GD32",b"gd32",b"ARM",b"Cortex",b"HAL",b"StdPeriph",b"SPI",b"QCA7005",b"QCA7000",b"INT6300",b"IS31",b"SECC",b"EVCC",b"evcc",b"secc",b"bms",b"BMS",b"CAN_",b"can_",b"CHAdeMO",b"chademo",b"0x2.01",b"boot",b"Boot",b"BOOT",b"IAP",b"iap",b"update",b"Update",b"OTA"]:
    idxs=[m.start() for m in re.finditer(re.escape(p),dec)]
    if idxs:
        i=idxs[0]; ctx=dec[max(0,i-6):i+len(p)+14]
        ctx=''.join(chr(x) if 32<=x<127 else '.' for x in ctx)
        print(f"{p.decode():10s} x{len(idxs):4d} @0x{i:06x}: {ctx!r}")