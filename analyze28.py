"""Disassemble a decoded firmware region (Thumb-2, link base 0x08020000).

Usage: python3 analyze28.py firmware.bin <start_hex> <len_hex> [base_hex]
Needs capstone: nix-shell -p python3 python3Packages.capstone --run '...'
"""
import sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
dec=open(sys.argv[1],'rb').read()
start=int(sys.argv[2],16); ln=int(sys.argv[3],16)
base=int(sys.argv[4],16) if len(sys.argv)>4 else 0x08020000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
md.detail=True
for i in md.disasm(dec[start:start+ln], base+start):
    print(f"0x{i.address:08x} f+0x{i.address-base:06x}: {i.mnemonic:8s} {i.op_str}")