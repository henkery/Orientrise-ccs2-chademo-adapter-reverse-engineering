import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def disasm(off,length,label=""):
    print(f"--- disasm f+0x{off:06x}..+0x{length:x} {label} ---")
    for i in md.disasm(dec[off:off+length],BASE+off):
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:10s} {i.op_str}")
def hexdump(off,length):
    for a in range(off,off+length,16):
        row=dec[a:a+16]
        print(f"  f+0x{a:06x}: {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")
disasm(0x0009c0,0x180,"SDP request builder + NO TLS security decision")
print()
disasm(0x002320,0xC0,"MAC print context (adr@0x0023a2)")
print("\n== EVCCID thunk block raw hex f+0x0690a0..0x069110 ==")
hexdump(0x0690a0,0x70)
disasm(0x0690a0,0x50,"thunk block re-aligned")
