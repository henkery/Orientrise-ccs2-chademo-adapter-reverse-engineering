import sys, struct
dec=open(sys.argv[1],'rb').read(); n=len(dec)
def w(i): return struct.unpack_from('<I',dec,i)[0]
SRAM=(0x20000000,0x20030000); CCM=(0x10000000,0x10010000); FLASH=(0x08000000,0x08100000)
print("== real vector-table test: SP word followed by >=12 consecutive flash handler words ==")
found=[]
for i in range(0,n-64):
    a=w(i)
    if not (SRAM[0]<=a<=SRAM[1] or CCM[0]<=a<=CCM[1]): continue
    run=0
    for j in range(i+4, min(i+4+4*120, n-4), 4):
        v=w(j)
        if FLASH[0]<=v<FLASH[1]: run+=1
        else: break
    if run>=12: found.append((i,a,run))
print("  REAL vector tables:", [(hex(i),hex(a),r) for i,a,r in found] or "NONE")

print("\n== longest run of consecutive flash-range words anywhere (4-aligned) ==")
best=(0,0); run=0; start=0
for i in range(0,n-4,4):
    if FLASH[0]<=w(i)<FLASH[1]:
        if run==0: start=i
        run+=1
        if run>best[1]: best=(start,run)
    else: run=0
print(f"  longest run @0x{best[0]:06x} len={best[1]} (pointer tables, not a vector table unless SP-preceded)")