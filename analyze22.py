import sys, struct, re
dec=open(sys.argv[1],'rb').read(); n=len(dec)
def locs(v,w=4):
    tb=struct.pack('<I',v) if w==4 else struct.pack('<H',v); out=[]; st=0
    while True:
        i=dec.find(tb,st)
        if i<0: break
        out.append(i); st=i+1
    return out
print("== system-reset (SCB_AIRCR 0xE000ED0C + VECTKEY 0x05FAxxxx) ==")
for v,nm in [(0xE000ED0C,"AIRCR"),(0x05FA0000,"VECTKEY"),(0x05FA0004,"VECTKEY|SYSRESETREQ"),(0xE000ED00,"SCB")]:
    l=locs(v); print(f"  {nm:20s} 0x{v:08x}: {[hex(i) for i in l]}")

print("\n== UPG XOR-decode key / header magic in code ==")
for v,w,nm in [(0x232b,2,"key16 2B23"),(0x232b232b,4,"key32 rep"),(0x2424,2,"'$$'"),(0x2b00,2,"hdr 00 2B")]:
    l=locs(v,w); print(f"  {nm:14s}: {[hex(i) for i in l][:12]}")

print("\n== CRC peripheral 0x40023000 context ==")
for i in locs(0x40023000):
    print(f"  @0x{i:06x}: pool="+ ' '.join(f'{struct.unpack_from("<I",dec,j)[0]:08x}' for j in range(max(0,i-12),min(n-3,i+16),4)))

print("\n== flash sector-size/start const tables (0x4000/0x10000/0x20000 runs) ==")
# sector sizes: 16K,16K,16K,16K,64K,128K... look for the run
pat=struct.pack('<IIII',0x4000,0x4000,0x4000,0x4000)
i=dec.find(pat)
print("  four 0x4000 (16K) run at:", hex(i) if i>=0 else "none")
for v in (0x20000358,0x20000388):
    print(f"  SRAM struct 0x{v:08x} refs: {[hex(x) for x in locs(v)]}")

print("\n== flash-writer address literals (RAM-copy source / fn ptr) ==")
for v in (0x080B10AC,0x080B1020,0x080B1076,0x080B1094,0x080B1000):
    l=locs(v); print(f"  0x{v:08x}: {[hex(i) for i in l]}")

print("\n== 'process'/task names + reboot strings near usbdisk ==")
for p in [b"usbdisk",b"Usbdisk",b"USBdisk",b"upgrade",b"Upgrade",b"UPGRADE",b"SystemReset",b"system_reset",b"do_upgrade",b"firmware"]:
    idxs=[m.start() for m in re.finditer(re.escape(p),dec)]
    for i in idxs[:4]:
        c=dec[max(0,i-8):i+len(p)+24]; c=''.join(chr(x) if 32<=x<127 else '.' for x in c)
        print(f"  {p.decode():12s} @0x{i:06x}: {c!r}")