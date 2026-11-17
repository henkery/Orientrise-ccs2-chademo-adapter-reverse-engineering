import sys, struct
dec=open(sys.argv[1],'rb').read(); n=len(dec)
def w(i): return struct.unpack_from('<I',dec,i)[0]
SRAM=(0x20000000,0x20030000); CCM=(0x10000000,0x10010000); FLASH=(0x08000000,0x08100000)
print("== scan for Cortex-M vector table: [SP in SRAM/CCM][Reset in flash, odd] ==")
vt=[]
for i in range(0,n-8):
    a=w(i); b=w(i+4)
    if (SRAM[0]<=a<=SRAM[1] or CCM[0]<=a<=CCM[1]) and FLASH[0]<=b<FLASH[1] and (b&1):
        vt.append((i,a,b))
print("  vector-table candidates:", [(hex(i),hex(a),hex(b)) for i,a,b in vt] or "NONE")

print("\n== any plausible initial-SP word (SRAM/CCM top regions), any alignment ==")
sp=[]
for i in range(0,n-4):
    a=w(i)
    if a in (0x20030000,0x20020000,0x10010000,0x10008000) or (0x2002F000<=a<=0x20030000):
        sp.append((i,a))
print("  top-of-RAM SP candidates:", [(hex(i),hex(a)) for i,a in sp[:20]] or "NONE")

print("\n== count of ALL words in SRAM range (would be numerous if a 2nd image present) ==")
cnt=sum(1 for i in range(0,n-4,4) if SRAM[0]<=w(i)<SRAM[1])
print("  4-aligned SRAM-range words:", cnt)

print("\n== 'BOOT' string refs & any embedded-image / bootloader markers ==")
import re
for p in [b"BOOT",b"Boot",b"boot",b"Bootloader",b"bootloader",b"BOOTARM",b"$$BOOT",b"IAP",b"iap",b"Ymodem",b"ymodem",b"Xmodem",b"DFU",b"dfu",b"UART",b"uart",b"serial"]:
    idxs=[m.start() for m in re.finditer(re.escape(p),dec)]
    if idxs:
        for i in idxs[:3]:
            c=dec[max(0,i-6):i+len(p)+22]; c=''.join(chr(x) if 32<=x<127 else '.' for x in c)
            print(f"  {p.decode():10s} @0x{i:06x}: {c!r}")