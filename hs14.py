import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def disasm(off,length,label=""):
    print(f"--- disasm f+0x{off:06x}..+0x{length:x} {label} ---")
    for i in md.disasm(dec[off:off+length],BASE+off):
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:10s} {i.op_str}")
disasm(0x001c00,0x170,"CM_SLAC_PARM_REQ builder (EVHost MAC + RunID)")
print()
disasm(0x002440,0xD0,"SLAC INIT (modem MAC read?)")
