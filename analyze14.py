import sys, struct
dec=open(sys.argv[1],'rb').read(); n=len(dec)
# known string file offsets
strs={0x2596:"QCA7005",0x30102:"BOOT_UPG",0x3ea:"XIE22.00",0x12a5b:"ISO15118",0x2a52:"SLAC CP"}
# candidate (image_start_file_offset S, link_base B)
cands=[(0x0,0x08000000),(0x58,0x08000000),(0x400,0x08000000),
       (0x400,0x08020000),(0x58,0x08020000),(0x400,0x08008000),(0x400,0x08010000)]
# build set of all 32-bit LE words present (any alignment) for fast lookup
present=set()
for off in range(0,n-3):
    present.add(struct.unpack_from('<I',dec,off)[0])
print("== which (S,B) mapping makes string pointers resolve? ==")
for S,B in cands:
    hits=0; detail=[]
    for so,name in strs.items():
        if so<S: continue
        addr=B+(so-S)
        if addr in present or (addr|1) in present:
            hits+=1; detail.append(f"{name}->0x{addr:08x}")
    print(f"S=0x{S:03x} B=0x{B:08x}: {hits}/{len(strs)}  {detail}")