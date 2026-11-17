import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def disasm(off,length,label=""):
    print(f"--- disasm f+0x{off:06x}..+0x{length:x} {label} ---")
    for i in md.disasm(dec[off:off+length],BASE+off):
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:10s} {i.op_str}")
disasm(0x014560,0x130,"ISO SessionSetupReq builder (adr@0x014628 -> ssReq dbg)")
print()
disasm(0x00d0a0,0x120,"DIN SessionSetupReq builder (adr@0x00d11a -> ssReq dbg)")
