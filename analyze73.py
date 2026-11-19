#!/usr/bin/env python3
"""analyze73.py — RTOS identification + task-stat dump / task-creation trace (REPORT §8.7).

The debug string "OS Information | OSRdyTbl:%05x | RUN:..." (f+0x2f042) names OSRdyTbl — the
uC/OS-II ready table (uC/OS-III uses OSRdyList). This tool confirms the RTOS family from
internal-symbol strings, locates the task-stat dump function via xrefs to its header/format
strings and disassembles it to expose the TCB field offsets, and finds task-creation sites via
xrefs to the process-name strings (tcpip_process / led_process / PDS_PROCESS / iso1_..._process).
Uses the ground-truth base 0x0801FBFE+F (§5.16); app pools are plaintext verbatim.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze73.py firmware.bin'
"""
import sys, struct, re, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
TB = 0x0801FBFE
fw = open(sys.argv[1] if len(sys.argv)>1 else 'firmware.bin','rb').read(); N=len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def u16(o): return struct.unpack_from('<H',fw,o)[0]
def u32(o): return struct.unpack_from('<I',fw,o)[0]
def rt(f): return TB+f
def ascii_at(o,n=48):
    if 0<=o<N:
        s=fw[o:o+n].split(b'\x00')[0]
        if len(s)>=3 and all(32<=c<127 for c in s): return s.decode()
    return None

print("== uC/OS-II / III internal-symbol strings ==")
syms=[b'OSRdyTbl',b'OSRdyGrp',b'OSRdyList',b'OSTCBCur',b'OSTCBHighRdy',b'OSTCBNext',b'OSTCBPrev',
      b'OSTCBStk',b'OSTCBPrio',b'OSTCBStat',b'OSTCBDly',b'OSTCBName',b'OSPrioCur',b'OSPrioHighRdy',
      b'OSIntNesting',b'OSLockNesting',b'OSRunning',b'OSTime',b'OSIdleCtr',b'OSCtxSwCtr',
      b'OSTaskStatStk',b'OSTaskStkInit',b'OS_Sched',b'OSCtxSw',b'OSIntCtxSw',b'OSTaskCreate',
      b'OSTaskDel',b'OSTaskSuspend',b'OSTaskResume',b'OSTimeDly',b'OSSem',b'OSMbox',b'OSQ',
      b'OSFlag',b'OSMutex',b'OS_ENTER_CRITICAL',b'OS_EXIT_CRITICAL',b'OS_CPU_SR',b'Micrium',
      b'uC/OS',b'uC/OS',b'UCOS',b'OS_VERSION',b'OSVersion',b'OSStatTask',b'OSStat',b'OS_TASK',
      b'OSRdy',b'OSTCB',b'OSPrio',b'OSIdle',b'OSTick',b'OSCfg',b'OS_CFG']
found={}
for p in syms:
    idx=fw.find(p); hits=[]
    while idx>=0 and len(hits)<4: hits.append(idx); idx=fw.find(p,idx+1)
    if hits:
        found[p]=hits
        ctx=fw[hits[0]:hits[0]+50].split(b'\x00')[0]
        print(f"  {p.decode():18s}: f+0x{hits[0]:05x} (0x{rt(hits[0]):08X}) {ctx!r}")
if not found: print("  (none)")

# ---- xref scan: find code loading a given runtime address (movw/movt, LDR pool, ADR) ----
def xrefs_to(addr):
    res=[]; movw_pending={}
    for o in range(0,N-4,2):
        h1=u16(o)
        if (h1&0xFBF0) in (0xF240,0xF2C0):
            ins=list(md.disasm(fw[o:o+4],rt(o),count=1))
            if ins and ins[0].mnemonic in ('movw','movt') and len(ins[0].operands)==2:
                i=ins[0]; reg=i.operands[0].reg; imm=i.operands[1].imm&0xFFFF
                if i.mnemonic=='movw': movw_pending[reg]=(imm,o)
                elif reg in movw_pending:
                    lo,fo=movw_pending.pop(reg)
                    if ((imm<<16)|lo)==addr: res.append((fo,'movw/movt'))
        elif (h1&0xF800)==0xA000:                    # ADR T1 (ADD Rd,PC,#imm8*4)
            t=((rt(o)+4)&~3)+(h1&0xFF)*4
            if t==addr: res.append((o,'adrT1'))
        elif (h1&0xF800)==0x4800:
            pca=((rt(o)+4)&~3)-TB                    # runtime-aligned PC+4 (base≡2 mod4, §5.16)
            t=pca+(h1&0xFF)*4
            if t+4<=N and u32(t)==addr: res.append((o,f'ldrT1@{t:05x}'))
        elif (h1&0xFF7F)==0xF85F:
            h2=u16(o+2); u=(h1>>7)&1
            pca=((rt(o)+4)&~3)-TB
            t=pca+((h2&0xFFF) if u else -(h2&0xFFF))
            if 0<=t and t+4<=N and u32(t)==addr: res.append((o,f'ldrT2@{t:05x}'))
        elif h1 in (0xF20F,0xF60F,0xF2AF,0xF6AF):    # wide ADR/ADD.W Rd,PC,#imm12
            ins=list(md.disasm(fw[o:o+4],rt(o),count=1))
            if ins and ins[0].mnemonic in ('adr','add','add.w','sub','sub.w'):
                for op in ins[0].operands:
                    if op.type==2 and op.imm:
                        t=((rt(o)+4)&~3)+op.imm
                        if t==addr: res.append((o,'adrWide'))
    # rodata pointer-table fallback: words equal to addr, then xrefs to those slots
    slots=[o for o in range(0,N-3,4) if u32(o)==addr]
    for sl in slots[:8]:
        for f,k in xrefs_to(rt(sl)):
            res.append((f,f'via-table@{sl:05x}:{k}'))
    return res

def disasm_range(start,end,label):
    print(f"\n== {label}: fw[0x{start:05x}:0x{end:05x}] @0x{rt(start):08X} ==")
    a=start
    while a<end:
        h1=u16(a); ins=list(md.disasm(fw[a:a+8],rt(a),count=1))
        if not ins and (h1&0xFFF0)==0xF380 and (u16(a+2)&0xFF00)==0x8800:
            sysm=u16(a+2)&0xFF; nm={8:'MSP',9:'PSP',0x10:'PRIMASK',0x14:'CONTROL'}.get(sysm,f'SYSm{sysm:02x}')
            print(f"  f+0x{a:05x} 0x{rt(a):08x}: msr      {nm}, r{h1&0xF}"); a+=4; continue
        if not ins:
            v=u32(a); s=ascii_at(v-TB) if 0x08000000<=v<0x08100000 else None
            print(f"  f+0x{a:05x} 0x{rt(a):08x}: .word    0x{v:08X}"+(f'  ; ->{s!r}' if s else '')); a+=2; continue
        i=ins[0]; note=''
        pca=((rt(a)+4)&~3)-TB                        # runtime-aligned PC+4 (base≡2 mod4, §5.16)
        if (h1&0xF800)==0x4800:
            t=pca+(h1&0xFF)*4; v=u32(t); s=ascii_at(v-TB) if 0x08000000<=v<0x08100000 else None
            note=f'   ; [f+0x{t:05x}=0x{v:08X}'+(f' ->{s!r}' if s else '')+']'
        elif (h1&0xFF7F)==0xF85F and i.size==4:
            h2=u16(a+2); u=(h1>>7)&1; t=pca+((h2&0xFFF) if u else -(h2&0xFFF)); v=u32(t)
            s=ascii_at(v-TB) if 0x08000000<=v<0x08100000 else None
            note=f'   ; [f+0x{t:05x}=0x{v:08X}'+(f' ->{s!r}' if s else '')+']'
        print(f"  f+0x{a:05x} 0x{rt(a):08x}: {i.mnemonic:9s} {i.op_str}{note}")
        a+=i.size

# ---- task-stat dump function ----
print("\n== xrefs to task-stat dump strings ==")
stat_strings={0x2f042:'OS Information/OSRdyTbl',0x2f07a:'Task RT BASE header',0x2f0ae:'task row format'}
dump_sites=[]
for fo,name in stat_strings.items():
    xr=xrefs_to(rt(fo))
    print(f"  {name} (0x{rt(fo):08X}): {[(hex(rt(f)),k) for f,k in xr]}")
    dump_sites += [f for f,_ in xr]
if dump_sites:
    lo=min(dump_sites); disasm_range(lo-0x40, lo+0x120, 'task-stat dump function (around first xref)')

# ---- task-creation sites via process-name xrefs ----
print("\n== process-name string xrefs (task creation) ==")
proc_names={}
for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{2,30}_(?:process|PROCESS)', fw):
    proc_names.setdefault(m.group().decode(), m.start())
for name,fo in proc_names.items():
    xr=xrefs_to(rt(fo))
    print(f"  {name:28s} f+0x{fo:05x} (0x{rt(fo):08X}): {[(hex(rt(f)),k) for f,k in xr]}")
    if xr:
        f0=xr[0][0]; disasm_range(f0-0x30, f0+0x60, f'creation site for {name}')