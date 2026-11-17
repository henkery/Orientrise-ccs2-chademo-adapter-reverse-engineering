import sys, struct, re
dec=open(sys.argv[1],'rb').read(); n=len(dec)
def strings_in(a,b,minlen=4):
    out=[]
    for m in re.finditer(rb'[\x20-\x7e]{%d,}'%minlen, dec[a:b]):
        out.append((a+m.start(), m.group().decode()))
    return out

print("== UPDATE / usbdisk module string table 0x2fe00-0x30e00 ==")
for off,s in strings_in(0x2fe00,0x30e00): print(f"0x{off:06x}  {s}")

print("\n== USB host region 0x3a400-0x3a800 ==")
for off,s in strings_in(0x3a400,0x3a800): print(f"0x{off:06x}  {s}")

print("\n== FAT / BPB region 0x37300-0x37400 ==")
for off,s in strings_in(0x37300,0x37400): print(f"0x{off:06x}  {s}")

def find(pat,label,ctx=24,limit=6):
    idxs=[m.start() for m in re.finditer(re.escape(pat),dec)]
    if idxs:
        print(f"\n[{label}] {len(idxs)} hit(s):")
        for i in idxs[:limit]:
            c=dec[max(0,i-8):i+len(pat)+ctx]
            c=''.join(chr(x) if 32<=x<127 else '.' for x in c)
            print(f"   0x{i:06x}: {c!r}")

print("\n== signature searches ==")
for p,l in [(b"$$DATA","UPG magic DATA"),(b"$$MAINARM","UPG MAINARM"),(b"$$BOOT","UPG BOOT tag"),
            (b"MAINARM","MAINARM"),(b"$$","$$ tag"),(b"ID6","ID6 variant"),
            (b"FatFs","FatFs"),(b"FATFS","FATFS"),(b"f_mount","f_mount"),(b"f_open","f_open"),
            (b"f_read","f_read"),(b"f_write","f_write"),(b"FR_OK","FR_OK"),(b"elm","FatFs author"),
            (b"SCSI","SCSI"),(b"INQUIRY","INQUIRY"),(b"REQUEST SENSE","REQ SENSE"),(b"TEST UNIT","TEST UNIT"),
            (b"READ CAPACITY","READ CAP"),(b"USBC","CBW sig"),(b"USBS","CSW sig"),(b"USBH","USBH"),
            (b"MSC","MSC"),(b"GET MAX LUN","GET MAX LUN"),(b"MODE SENSE","MODE SENSE"),
            (b"SystemReset","SystemReset"),(b"NVIC","NVIC"),(b"reboot","reboot"),(b"Reboot","Reboot"),
            (b"jump","jump"),(b"Jump","Jump"),(b"IAP","IAP"),(b"bootloader","bootloader"),
            (b"erase","erase"),(b"Erase","Erase"),(b"sector","sector"),(b"Sector","Sector"),
            (b"version","version"),(b"Version","Version"),(b"same","same ver"),(b"skip","skip"),
            (b"verify","verify"),(b"Verify","Verify"),(b"crc","crc"),(b"CRC","CRC"),(b"check","check")]:
    find(p,l)

print("\n== FLASH unlock keys (0x45670123 / 0xCDEF89AB) => flash programming present ==")
for key in (0x45670123,0xCDEF89AB):
    tb=struct.pack('<I',key); idxs=[]; st=0
    while True:
        i=dec.find(tb,st)
        if i<0: break
        idxs.append(i); st=i+1
    print(f"  0x{key:08x}: {[hex(i) for i in idxs]}")

print("\n== flash-region address literals (possible update targets) ==")
for addr in (0x08000000,0x08004000,0x08008000,0x08010000,0x08020000,0x08040000,0x08060000,0x08080000,0x080C0000,0x08100000,0x08180000,0x081C0000):
    tb=struct.pack('<I',addr); cnt=dec.count(tb)
    if cnt: print(f"  0x{addr:08x}: {cnt} literal(s)")