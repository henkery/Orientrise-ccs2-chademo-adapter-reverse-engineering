import sys, struct, collections
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
CAN1=0x40006400; CAN2=0x40006800

# register addresses of interest: core regs + TX mailboxes + filter banks
targets={}
for name,base in (("CAN1",CAN1),("CAN2",CAN2)):
    for off in range(0,0x1b0,4):
        targets[base+off]=f"{name}+0x{off:03x}"
for off in range(0x200,0x220,4):
    targets[CAN1+off]=f"FLT+0x{off:03x}"   # FMR FM1R FS1R FFA1R FA1R
for i in range(28):
    for r in (0,4):
        targets[CAN1+0x240+8*i+r]=f"F{i}R{r//4+1}"

occ=collections.defaultdict(list)
for off in range(0,n-3):
    w=struct.unpack_from('<I',dec,off)[0]
    if w in targets: occ[w].append(off)

print("== literal occurrences of CAN register addresses ==")
for w in sorted(occ):
    print(f"  0x{w:08x} {targets[w]:12s} @ "+", ".join(f"0x{o:06x}" for o in occ[w]))

# LDR (literal) T2: hw1 = 0xF85F | U<<7 ; target = Align(PC,4) +/- imm12
ldr_refs=collections.defaultdict(list)
for a in range(0x400,n-4,2):
    hw1=struct.unpack_from('<H',dec,a)[0]
    if (hw1&0xFF7F)!=0xF85F: continue
    hw2=struct.unpack_from('<H',dec,a+2)[0]
    imm12=hw2&0xFFF; U=(hw1>>7)&1; Rt=(hw2>>12)&0xF
    t=((a+4)&~3)+(imm12 if U else -imm12)
    if 0<=t<n-3:
        w=struct.unpack_from('<I',dec,t)[0]
        if w in targets: ldr_refs[w].append((a,Rt,t))

# MOVW/MOVT pairs building a CAN address
def imm16(hw1,hw2):
    return (((hw1>>4)&0xF)<<12)|(((hw1>>10)&1)<<11)|(((hw2>>12)&7)<<8)|(hw2&0xFF)
mov_refs=collections.defaultdict(list)
for a in range(0x402,n-4,2):
    hw1=struct.unpack_from('<H',dec,a)[0]
    if (hw1&0xFBF0)!=0xF2C0: continue   # MOVT
    hw2=struct.unpack_from('<H',dec,a+2)[0]
    Rd=(hw2>>8)&0xF
    p1=struct.unpack_from('<H',dec,a-2)[0]; p2=struct.unpack_from('<H',dec,a)[0]
    if (p1&0xFBF0)!=0xF240: continue    # MOVW right before
    if ((p2>>8)&0xF)!=Rd: continue
    v=(imm16(hw1,hw2)<<16)|imm16(p1,p2)
    if v in targets: mov_refs[v].append((a-2,Rd))

print("\n== code references (LDR-literal / MOVW+MOVT) ==")
regions=collections.Counter()
for w in sorted(targets):
    refs=[(a,f"ldr r{Rt},[pc,#..] pool@0x{t:06x}") for a,Rt,t in ldr_refs.get(w,[])]
    refs+=[(a,f"movw/movt r{Rd}") for a,Rd in mov_refs.get(w,[])]
    if not refs: continue
    print(f"  0x{w:08x} {targets[w]:12s}:")
    for a,d in sorted(refs):
        print(f"    code@0x{a:06x} (0x{BASE+a:08x})  {d}")
        regions[a>>10]+=1
print("\n== code regions (1KB buckets) touching CAN regs ==")
for b,c in sorted(regions.items()):
    print(f"  0x{b<<10:06x}-0x{(b<<10)+0x3ff:06x}  x{c}")