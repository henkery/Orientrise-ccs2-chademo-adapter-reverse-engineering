#!/usr/bin/env python3
"""
analyze98.py — Agent K reproducible decoder / checker for the C013 lwIP TCP
reliability layer.  RESEARCH ONLY (reads decoded_c013.bin; writes nothing to firmware).

Loads the plaintext Thumb-2 image, re-derives every load-bearing constant / pcb offset /
call target from the disassembly, asserts it against the recovered value, dumps a few key
functions as evidence, prints the mechanism + config + pcb layout, and ends with
"N checks, M failures".

Run:  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze98.py'
Self-contained (embeds the helpers.py pool/dis logic; only needs capstone).
"""
import os, struct, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

FWPATH = '.qwen/tmp/c013/decoded_c013.bin'
TB = 0x0801FBFE                       # true link base; rt(F) = TB + F
fw = open(FWPATH, 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True

def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
def pool(o):
    """Resolve an LDR-literal at file offset o to its pool word (runtime-PC aligned)."""
    h = u16(o)
    if (h & 0xF800) == 0x4800:                      # T1
        p = (((rt(o)+4) & ~3) - TB) + (h & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    if (h & 0xFF7F) == 0xF85F and o+4 <= N:         # T2
        U = (h >> 7) & 1; imm = u16(o+2) & 0xFFF; b = ((rt(o)+4) & ~3)
        p = (b+imm if U else b-imm) - TB
        if 0 <= p and p+4 <= N: return u32(p)
    return None
def tag(w):
    return (" FLASH" if 0x08000000 <= w < 0x08100000 else
            " RAM" if 0x20000000 <= w < 0x20030000 else "")

# ---- instruction accessors (runtime addresses) ----
def ins_at(a):
    ins = dis(a-TB); return ins[0] if ins else None
def mn_at(a):
    i = ins_at(a); return i.mnemonic if i else None
def imm_at(a):
    i = ins_at(a)
    if i is None: return None
    imms = [o.imm for o in i.operands if o.type == 2]   # ARM_OP_IMM
    return imms[-1] if imms else None
def memdisp_at(a):
    i = ins_at(a)
    if i is None: return None
    for o in i.operands:
        if o.type == 3: return o.mem.disp               # ARM_OP_MEM
    return None
def poolword_at(a): return pool(a-TB)
def target_at(a):
    i = ins_at(a)
    if i is None or i.mnemonic not in ('bl', 'b', 'b.w'): return None
    try: return int(i.op_str.replace('#', ''), 0)
    except ValueError: return None
def bytes_at(a, n): o = a-TB; return fw[o:o+n]
def u32_at(a): return u32(a-TB)

# ---- check framework ----
CHECKS = []
def check(name, got, want):
    ok = (got == want)
    CHECKS.append((name, ok))
    def fmt(v):
        if isinstance(v, int): return f"0x{v:X}"
        if isinstance(v, bytes): return v.hex(' ')
        return repr(v)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: got={fmt(got)} want={fmt(want)}")
    return ok

def dumpn(addr, n, label):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr-TB; mv = {}
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; ex = ""; w = pool(a)
        if w is not None: ex = f"  ; =0x{w:08X}{tag(w)}"
        if i.mnemonic in ('movw', 'movt') and len(i.operands) == 2:
            reg = i.operands[0].reg; imm = i.operands[1].imm & 0xFFFF
            if i.mnemonic == 'movw': mv[reg] = imm; ex = f"  ; lo=0x{imm:04x}"
            elif reg in mv:
                full = (imm << 16) | mv.pop(reg); ex = f"  ; =0x{full:08X}{tag(full)}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:9s} {i.op_str}{ex}")
        a += i.size
    return a

print("="*78)
print("Agent K — C013 lwIP TCP reliability decoder")
print(f"image: {FWPATH}  ({N} bytes / 0x{N:X})   TB=0x{TB:08X}")
print("="*78)

# ============================================================================
print("\n### Item 7 — CONFIG constants (re-derived from immediates) ###")
check("TCP_MSS=1460 (parse_opt clamp)",            imm_at(0x0809965A), 0x5b4)
check("TCP_WND=11680 (tcp_connect)",               imm_at(0x080920AC), 0x2da0)
check("TCP_WND=11680 (tcp_alloc)",                 imm_at(0x08092266), 0x2da0)
check("TCP_SND_BUF=14600 (tcp_alloc)",             imm_at(0x0809225C), 0x3908)
check("TCP_SND_QUEUELEN=40 (enqueue_flags)",       imm_at(0x08092518), 0x28)
check("TCP_SND_QUEUELEN=40 (tcp_write)",           imm_at(0x080926BA), 0x28)
check("TCP_OVERSIZE=1460 (prealloc +0x5b7 align)", imm_at(0x08092616), 0x5b7)
check("TCP_TMR_INTERVAL=250ms (timerneeded)",      imm_at(0x0808FE72), 0xfa)
check("TCP_TMR_INTERVAL=250ms (callback re-arm)",  imm_at(0x0808FE9A), 0xfa)
check("TCP_SLOW_INTERVAL=500ms (slowtmr)",         imm_at(0x08091566), 0x1f4)
check("TCP_SYNMAXRTX=3 (slowtmr)",                 imm_at(0x080915A2), 3)
check("TCP_MAXRTX=4 (slowtmr)",                    imm_at(0x080915AE), 4)
check("TIME_WAIT=240 ticks (slowtmr)",             imm_at(0x080917C4), 0xf0)
check("initial cwnd=4380 (SYN_SENT arm)",          imm_at(0x080997B4), 0x111c)
check("alloc mss init=536",                        imm_at(0x08092274), 0x218)
check("alloc rto init=2",                          imm_at(0x0809227A), 2)
check("alloc cwnd init=1",                         imm_at(0x0809228E), 1)
check("tcp_new prio=0x40",                         imm_at(0x080922B4), 0x40)
check("ephemeral port lo=0xc000 (new_port)",       imm_at(0x08091CE8), 0xc000)
check("ephemeral port hi=0xffff (new_port)",       imm_at(0x08091CE4), 0xffff)
check("eff_send_mss IPv4 overhead=40",             imm_at(0x08091F8E), 0x28)
check("eff_send_mss IPv6 overhead=60",             imm_at(0x08091FB0), 0x3c)
check("tcp_rst flags=0x5014 (RST|ACK,hdrlen5)",    imm_at(0x08092E26), 0x5014)
check("sizeof(tcp_pcb)=0xb8 (memset size)",        imm_at(0x08092254), 0xb8)
check("alloc kill-prio cap=0x7f",                  imm_at(0x08092216), 0x7f)
check("MEMP pool count=12",                        imm_at(0x08090934), 0xc)

print("\n### Item 7 — flash tables (raw bytes) ###")
check("tcp_backoff {1,2,3,4,5,6,7,7,7,7,7,7,7}",
      bytes_at(0x080B0400, 13), bytes([1,2,3,4,5,6,7,7,7,7,7,7,7]))
check("persist_backoff {3,6,12,24,48,96,120}",
      bytes_at(0x080B03CC, 7), bytes([3,6,12,24,48,96,120]))
check("pcb-list table {listen,bound,active,tw}",
      [u32_at(0x080B0410+4*k) for k in range(4)],
      [0x20000B18, 0x20000B14, 0x20000B1C, 0x20000B20])
check("tcp_process tbb state table bytes",
      bytes_at(0x0809976C, 8), bytes([0x04,0x7b,0xe9,0xf1,0xef,0xe9,0xee,0xed]))

print("\n### Globals / ISS / timer base ###")
check("slowtmr globals base pool=0x20000B04",      poolword_at(0x08091560), 0x20000B04)
check("tcp_ticks @ base+0xc (=0x20000B10)",        memdisp_at(0x0809156A), 0xc)
check("next_iss globals base pool=0x20000B04",     poolword_at(0x08091FB4), 0x20000B04)
check("next_iss ldrd iss,ticks @ base+8",          memdisp_at(0x08091FB6), 8)
check("fasttmr loads listen base=0x20000B18",      poolword_at(0x08091B12), 0x20000B18)
check("fasttmr subs 0x14 -> globals 0x20000B04",   imm_at(0x08091B14), 0x14)
check("memp pool table pool=0x080B039C",           poolword_at(0x0809093C), 0x080B039C)

print("\n### Item 8 — tcp_pcb offsets (absolute, base=pcb) ###")
check("rcv_nxt @ pcb+0x44",                        memdisp_at(0x0809978E), 0x44)
check("cwnd @ pcb+0x68",                           memdisp_at(0x080997DC), 0x68)
check("connected_cb @ pcb+0xa4",                   memdisp_at(0x08099808), 0xa4)
check("mss @ pcb+0x52",                            memdisp_at(0x080997B8), 0x52)
check("snd_lbb @ pcb+0x78 (enqueue seqno)",        memdisp_at(0x08092542), 0x78)
check("tcp_arg -> callback_arg @ pcb+0x30",        memdisp_at(0x080922CA), 0x30)
check("tcp_recv -> recv_cb @ pcb+0xa0",            memdisp_at(0x080922D2), 0xa0)
check("tcp_sent -> sent_cb @ pcb+0x9c",            memdisp_at(0x080922DC), 0x9c)
check("tcp_err -> err_cb @ pcb+0xac",              memdisp_at(0x080922E6), 0xac)
check("alloc r4 := pcb+0x34 (adds)",               imm_at(0x0809225A), 0x34)
check("snd_buf store disp 0x4c -> pcb+0x80",       memdisp_at(0x08092262), 0x4c)
check("rcv_wnd store disp 0x14 -> pcb+0x48",       memdisp_at(0x0809226C), 0x14)
check("rcv_ann_wnd store disp 0x16 -> pcb+0x4a",   memdisp_at(0x0809226A), 0x16)

print("\n### Items 1/2/4/5 — function entries & call graph ###")
for name, a in [("tcp_input",0x08099BA6),("tcp_output",0x08092B60),
                ("tcp_write",0x0809263C),("tcp_slowtmr",0x0809155C),
                ("tcp_connect",0x08091FC0),("tcp_receive",0x08098EDC),
                ("tcp_recved",0x08091A28)]:
    check(f"{name} entry is push", (mn_at(a) or '').startswith('push'), True)
check("tcp_close = movs r1,#1",                    imm_at(0x08091CD8), 1)
check("tcp_close tail b -> close_shutdown 0x91BFA",target_at(0x08091CDA), 0x08091BFA)
check("tcp_alloc memset call -> 0x9E958",          target_at(0x08092256), 0x0809E958)
check("tcp_tmr calls tcp_fasttmr 0x91B10",         target_at(0x08091B8A), 0x08091B10)
check("tcp_tmr odd-tick B -> tcp_slowtmr 0x9155C", target_at(0x08091BA0), 0x0809155C)
check("tcp_tmr odd test lsls #0x1f",               imm_at(0x08091B98), 0x1f)
check("fasttmr TF_ACK_DELAY test lsls #0x1f",      imm_at(0x08091B32), 0x1f)
check("fasttmr clear ACK_DELAY|ACK_NOW bic #3",    imm_at(0x08091B48), 3)
check("fasttmr TF_CLOSEPEND test lsls #0x1c",      imm_at(0x08091B52), 0x1c)
check("fasttmr CLOSEPEND -> close-FIN 0x917F0",    target_at(0x08091B60), 0x080917F0)
check("fasttmr refused_data retry -> 0x91A9A",     target_at(0x08091B72), 0x08091A9A)

print("\n### Item 9 — adapter GLUE call targets ###")
check("glue write wrapper -> tcp_write 0x9263C",   target_at(0x08060B60), 0x0809263C)
check("glue write wrapper -> tcp_output 0x92B60",  target_at(0x08060B6A), 0x08092B60)
check("glue recv_cb -> tcp_recved 0x91A28",        target_at(0x08060AA4), 0x08091A28)

# ============================================================================
# Evidence dumps
# ============================================================================
dumpn(0x08091B88, 13, "tcp_tmr (fasttmr every 250ms; odd tick -> slowtmr 500ms)")
dumpn(0x08092254, 16, "tcp_alloc memset+init (TCP_SND_BUF / TCP_WND / mss / rto / cwnd)")
dumpn(0x0809155C, 12, "tcp_slowtmr head (tcp_ticks++ @0x20000B10, SLOW_INTERVAL=500)")
dumpn(0x080997B4, 12, "SYN_SENT -> ESTABLISHED initial cwnd = min(max(2*mss,4380),4*mss)")

# ============================================================================
# Recovered mechanism / config / layout summary
# ============================================================================
print("\n" + "="*78)
print("RECOVERED MECHANISM (lwIP 2.1.x raw-API TCP, dual-stack IPv4/IPv6)")
print("="*78)
print("""
State machine : tcp_input 0x08099BA6 -> tcp_process 0x080996B8 (tbb @0x0809976C)
                -> tcp_receive 0x08098EDC ; LISTEN->tcp_listen_input 0x08099A74,
                TIME_WAIT->tcp_timewait_input 0x0809A05E.
Handshake     : SYN seqno = snd_lbb = iss-1 ; on SYN/ACK ackno==lastack+1 ->
                rcv_nxt=seqno+1, state=ESTABLISHED, cwnd=4380, connected_cb(arg,pcb,OK).
Output        : tcp_output 0x08092B60 -> tcp_output_segment 0x08092A6E ;
                seq=htonl(snd_lbb), ack=htonl(rcv_nxt), wnd=htons(rcv_ann_wnd);
                window=min(snd_wnd,cwnd); Nagle unless NODELAY/INFR.
Write         : tcp_write 0x0809263C COPY=1 -> PBUF_RAM+memcpy (REF->PBUF_ROM);
                limits snd_buf=14600, snd_queuelen<40; segsize=min(mss,snd_wnd_max/2).
Timers        : sys_timeout(250ms) -> tcp_tmr 0x08091B88 ; fasttmr 0x08091B10 every
                tick (delayed-ACK / TF_CLOSEPEND / refused retry); slowtmr 0x0809155C
                every odd tick (500ms): RTO=(sa+sv/8)<<backoff[nrtx], rexmit, keepalive,
                ZWP, ooseq/TIME_WAIT timeouts, poll.
Congestion    : slow-start cwnd+=mss ; cong-avoid cwnd+=mss*mss/cwnd ;
                RTO collapse ssthresh=max(min(cwnd,snd_wnd)/2,2*mss), cwnd=mss ;
                fast-recovery cwnd=ssthresh+3*mss (TF_INFR).
Close         : tcp_close 0x08091CD8 -> close_shutdown ; unread data -> RST+purge ;
                graceful -> send_fin 0x080925A4 (FIN_WAIT_1 / LAST_ACK) / TIME_WAIT.
""")
print("CONFIG: MSS=1460 WND=11680 SND_BUF=14600 SND_QUEUELEN=40 OVERSIZE=1460")
print("        TMR=250ms SLOW=500ms SYNMAXRTX=3 MAXRTX=4 TIME_WAIT=240ticks(120s)")
print("        eff_send_mss=1 LISTEN_BACKLOG=0 timestamps/SACK/wscale=OFF ports 49152-65535")
print("PCB (184B): rcv_nxt@0x44 rcv_wnd@0x48 rcv_ann_wnd@0x4a mss@0x52 rto@0x60")
print("        lastack@0x64 cwnd@0x68 ssthresh@0x6a snd_nxt@0x6c snd_lbb@0x78 snd_wnd@0x7c")
print("        snd_buf@0x80 snd_queuelen@0x82 unsent@0x88 unacked@0x8c ooseq@0x90")
print("        refused_data@0x94 sent_cb@0x9c recv_cb@0xa0 connected_cb@0xa4 poll_cb@0xa8 err_cb@0xac")
print("GLOBALS: tcp_ticks@0x20000B10 iss@0x20000B0C active_pcbs@0x20000B1C tw_pcbs@0x20000B20")
print("OPEN [?]: MEMP_NUM_TCP_SEG, exact lwIP patch, initial iss RAM value, send_fin last-seg")
print("        bit test, keepalive 675000/75000 semantics, alloc sa init, create_segment r6=4.")

# ============================================================================
npass = sum(1 for _, ok in CHECKS if ok)
nfail = sum(1 for _, ok in CHECKS if not ok)
print("\n" + "="*78)
if nfail:
    print("FAILED CHECKS:")
    for name, ok in CHECKS:
        if not ok: print("  - " + name)
print(f"{len(CHECKS)} checks, {nfail} failures")
print("="*78)
sys.exit(1 if nfail else 0)