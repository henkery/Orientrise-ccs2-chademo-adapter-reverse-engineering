import sys, struct, collections
dec=open(sys.argv[1],'rb').read(); n=len(dec)
BASE=0x08020000

# Build the set of bxCAN BTR words that yield an exact standard baud at a plausible
# APB1 clock. BTR: BRP[9:0]=psc-1, TS1[19:16]=BS1-1, TS2[22:20]=BS2-1, SJW[25:24]=SJW-1.
btr_map=collections.defaultdict(list)   # btr_word -> [(baud,apb1,psc,bs1,bs2)]
for apb1 in (30e6,36e6,42e6,45e6,48e6,60e6,84e6,90e6):
    for baud in (125e3,250e3,500e3,1e6):
        for psc in range(1,65):
            if (apb1/baud)%psc: continue
            total=int(apb1/baud/psc)
            if not (3<=total<=25): continue
            for bs2 in range(1,9):
                bs1=total-1-bs2
                if not (1<=bs1<=16): continue
                sp=(1+bs1)/total
                if not (0.75<=sp<=0.90): continue
                for sjw in (1,2):
                    w=(psc-1)|((bs1-1)<<16)|((bs2-1)<<20)|((sjw-1)<<24)
                    btr_map[w].append((int(baud),int(apb1),psc,bs1,bs2,sjw))

# scan for these words at 4- and 2-byte alignment, cluster within 16B
hits=[]
for off in range(0x400,n-3,2):
    w=struct.unpack_from('<I',dec,off)[0]
    if w in btr_map: hits.append((off,w))
clusters=[]; cur=[]
for off,w in hits:
    if cur and off-cur[-1][0]>16: clusters.append(cur); cur=[]
    cur.append((off,w))
if cur: clusters.append(cur)
print("== BTR-value clusters (candidate baud tables) ==")
for cl in clusters:
    if len(cl)<2: continue
    print(f"  table @ f+0x{cl[0][0]:06x}:")
    for off,w in cl:
        opts=btr_map[w]
        # prefer 42/45 MHz interpretations
        s="; ".join(f"{b//1000}k APB1={a//1000000}M psc{p} BS1={b1} BS2={b2} SJW{j}" for b,a,p,b1,b2,j in opts[:4])
        print(f"    f+0x{off:06x} BTR 0x{w:08x}  -> {s}")

# SysTick: find literal 0xE000E010/14/18 and the LOAD value written
print("\n== SysTick references (0xE000E010/14/18) ==")
for off in range(0x400,n-3,4):
    w=struct.unpack_from('<I',dec,off)[0]
    if w in (0xE000E010,0xE000E014,0xE000E018):
        print(f"  pool f+0x{off:06x} = 0x{w:08x}")