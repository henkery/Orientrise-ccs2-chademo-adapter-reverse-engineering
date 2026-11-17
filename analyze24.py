import sys, struct
dec=open(sys.argv[1],'rb').read(); n=len(dec)
def sx(v,b): return v-(1<<b) if v&(1<<(b-1)) else v
callers=[]
for a in range(0x400,n-4,2):
    hw1=struct.unpack_from('<H',dec,a)[0]; hw2=struct.unpack_from('<H',dec,a+2)[0]
    if (hw1>>11)!=0x1e: continue
    m=hw2&0xD000
    if m not in (0xD000,0x8000): continue
    S=(hw1>>10)&1; imm10=hw1&0x3ff
    J1=(hw2>>13)&1; J2=(hw2>>11)&1; imm11=hw2&0x7ff
    I1=1-((J1^S)&1); I2=1-((J2^S)&1)
    off=(S<<24)|(I1<<23)|(I2<<22)|(imm10<<12)|(imm11<<1)
    off=sx(off,25)
    tgt=(a+4)+off
    if 0x91000<=tgt<=0x911a0:
        callers.append((a,tgt,'BL' if m==0xD000 else 'B.W'))
print("== BL/B.W callers targeting flash-writer region 0x91000-0x911a0 ==")
for a,t,k in callers: print(f"  {k} @0x{a:06x} -> 0x{t:06x}")
print("total:",len(callers))

# Also: who references the sector-table SRAM struct setup / a RAM copy of the writer?
print("\n== BL/B.W callers targeting the usbdisk string/code area & reset fn 0x691c6 ==")
rst=[]
for a in range(0x400,n-4,2):
    hw1=struct.unpack_from('<H',dec,a)[0]; hw2=struct.unpack_from('<H',dec,a+2)[0]
    if (hw1>>11)!=0x1e: continue
    if (hw2&0xD000)!=0xD000: continue
    S=(hw1>>10)&1; imm10=hw1&0x3ff; J1=(hw2>>13)&1; J2=(hw2>>11)&1; imm11=hw2&0x7ff
    I1=1-((J1^S)&1); I2=1-((J2^S)&1)
    off=sx((S<<24)|(I1<<23)|(I2<<22)|(imm10<<12)|(imm11<<1),25)
    tgt=(a+4)+off
    if tgt==0x691c6: rst.append(a)
print("  callers of 0x691c6 (tail-call after sys-init):",[hex(x) for x in rst])