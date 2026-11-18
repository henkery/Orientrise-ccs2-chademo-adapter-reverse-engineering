import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
dec=open(sys.argv[1],'rb').read(); n=len(dec); BASE=0x08020000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
# find every mov.w Rd,#0x40000000 (TIM2 base): hw1=0xF04F, hw2&0xF0FF==0x4040
sites=[]
for a in range(0x400,n-4,2):
    h1=struct.unpack_from('<H',dec,a)[0]; h2=struct.unpack_from('<H',dec,a+2)[0]
    if h1==0xF04F and (h2&0xF0FF)==0x4080: sites.append(a)
print("mov.w #0x40000000 (TIM2) sites:",len(sites))
for a in sites:
    # disassemble a window after, look for PSC(+0x28)/ARR(+0x2c)/CR1(+0) writes
    ins=list(md.disasm(dec[a:a+0x60],BASE+a))
    rel=[i for i in ins if ('#0x28]' in i.op_str or '#0x2c]' in i.op_str) and i.mnemonic.startswith('str')]
    if rel:
        print(f"\n  TIM2 init @ f+0x{a:06x}:")
        for i in ins[:22]:
            print(f"    0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:8s} {i.op_str}")