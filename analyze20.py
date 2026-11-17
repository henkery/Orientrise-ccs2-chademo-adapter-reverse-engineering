import sys, struct
dec=open(sys.argv[1],'rb').read(); n=len(dec)
def locs(v):
    tb=struct.pack('<I',v); out=[]; st=0
    while True:
        i=dec.find(tb,st)
        if i<0: break
        out.append(i); st=i+1
    return out
print("== literal locations (file offsets) ==")
for v,name in [(0x40023C00,"FLASH_R base"),(0x40023C08,"FLASH_KEYR"),(0x40023C10,"FLASH_CR"),
               (0x40023C0C,"FLASH_SR"),(0x45670123,"KEY1"),(0xCDEF89AB,"KEY2"),
               (0x08000000,"boot base"),(0x08004000,"sec1"),(0x08008000,"sec2"),(0x0800C000,"sec3"),
               (0x08010000,"sec4"),(0x08020000,"app base/sec5"),(0x08040000,"sec6"),(0x08060000,"sec7"),
               (0x08080000,"sec8"),(0x080A0000,"sec9"),(0x080C0000,"sec10"),(0x080E0000,"sec11"),
               (0x08100000,"1MB end"),(0x20000000,"SRAM base"),(0x40023000,"CRC periph")]:
    l=locs(v)
    if l: print(f"  {name:16s} 0x{v:08x}: {[hex(i) for i in l]}")

print("\n== flash-program function near KEY1/KEY2 pool (0x9118e) : disasm-ready hex 0x910c0-0x911a0 ==")
b=dec[0x910c0:0x911a0]
for i in range(0,len(b),16):
    row=b[i:i+16]
    print(f"{0x910c0+i:06x}: {' '.join(f'{x:02x}' for x in row)}")

print("\n== context around each app-base(0x08020000) and boot-base(0x08000000) literal ==")
for v in (0x08020000,0x08000000,0x080c0000,0x08010000,0x08004000):
    for i in locs(v):
        print(f"  0x{v:08x} @0x{i:06x}: pool words around = "+
              ' '.join(f'{struct.unpack_from("<I",dec,j)[0]:08x}' for j in range(max(0,i-16),min(n-3,i+20),4)))