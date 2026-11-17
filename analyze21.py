import sys, struct
dec=open(sys.argv[1],'rb').read(); n=len(dec)
B0=0x08020000
def locs(v):
    tb=struct.pack('<I',v); out=[]; st=0
    while True:
        i=dec.find(tb,st)
        if i<0: break
        out.append(i); st=i+1
    return out
print("== code refs to update-module strings (addr = 0x08020000 + fileoff) ==")
for fo,name in [(0x2ffee,"Write flash error"),(0x3001a,"UPGRADE Finished"),(0x30102,"BOOT.UPG"),
                (0x3011a,"MAIN.UPG"),(0x30132,"MAIN_ID6.UPG"),(0x2ff56,"file Open err"),
                (0x2ffc1,"file Read err"),(0x2ffa6,"file size err"),(0x2ff76,"has been updated"),
                (0x30d72,"UPGRADE hdr fmt"),(0x302b6,"Exit usbdisk"),(0x302d2,"usbdisk timeout"),
                (0x2feb6,"Disk capacity"),(0x300c2,"Cannot init FS"),(0x300bd,"0:/")]:
    a=B0+fo
    l=locs(a)+locs(a|1)
    if l: print(f"  {name:18s} addr 0x{a:08x}: literal(s) at {[hex(i) for i in l]}")

print("\n== SRAM 0x20000358 refs (flash-writer pool) & nearby RAM exec hints ==")
for v in (0x20000358,0x20000000):
    l=locs(v)
    print(f"  0x{v:08x}: {[hex(i) for i in l]}")

print("\n== IWDG / watchdog + reset strings (failsafe hints) ==")
import re
for p in [b"IWDG",b"iwdg",b"Watchdog",b"watchdog",b"WWDG",b"RESET",b"Reset",b"reset",b"DEEP SLEEP",b"power down",b"Power"]:
    idxs=[m.start() for m in re.finditer(re.escape(p),dec)]
    for i in idxs[:3]:
        c=dec[max(0,i-6):i+len(p)+20]; c=''.join(chr(x) if 32<=x<127 else '.' for x in c)
        print(f"  {p.decode():10s} @0x{i:06x}: {c!r}")