import sys, struct, collections
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000
# GB/T 27930-2015 message set: name -> (29-bit ID). chg SA=0x56, BMS SA=0xF4.
GBT={
 "CHM":0x1826F456,"CRM":0x1801F456,"CTS":0x1807F456,"CML":0x1808F456,
 "CRO":0x1809F456,"CCS":0x1812F456,"CST":0x181AF456,"CSD":0x181DF456,"CEM":0x181EF456,
 "BHM":0x182756F4,"BRM":0x1C0256F4,"BCP":0x1C0656F4,"BRO":0x100956F4,
 "BCL":0x181056F4,"BCS":0x181156F4,"BSM":0x181356F4,"BST":0x101956F4,
 "BSD":0x181C56F4,"BEM":0x181E56F4,
 "TP.CM_chg":0x1CECF456,"TP.CM_bms":0x1CEC56F4,"TP.DT_bms":0x1CEB56F4,"TP.DT_chg":0x1CEBF456,
}
# index every 2-aligned 32-bit word -> offsets (catches odd-aligned tables)
idx=collections.defaultdict(list)
for off in range(0x400,n-3,2):
    idx[struct.unpack_from('<I',dec,off)[0]].append(off)
print("== GB/T 27930 exact-ID matches (32-bit word, any 2B alignment) ==")
for name,eid in GBT.items():
    offs=idx.get(eid,[])
    # also BEM may use prio2 (0x081E56F4)
    if name=="BEM": offs=offs+idx.get(0x081E56F4,[])
    if offs:
        print(f"  {name:10s} 0x{eid:08x}  @ "+", ".join(f"0x{o:06x}" for o in offs[:8]))
    else:
        print(f"  {name:10s} 0x{eid:08x}  (not found as constant)")

print("\n== pointers into the BTR/config block (flash 0x0808f05c..0x0808f070) ==")
for off in range(0x400,n-3,2):
    w=struct.unpack_from('<I',dec,off)[0]
    if 0x0808f05c<=w<=0x0808f070:
        print(f"  f+0x{off:06x} -> 0x{w:08x} (config+0x{w-0x0808f05c:x})")