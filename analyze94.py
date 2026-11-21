#!/usr/bin/env python3
"""analyze94.py — live UDP/TCP/IPv6 + mbedTLS transport (REPORT §5.9, Agent G/H).

Re-derives from the C013 firmware bytes the GATED network transport that carries the CCS2 EVCC
session between the QCA7005 PLC Ethernet transport (analyze91) and the DIN EXI session
(analyze93). Replicated INERT in custom_fw/src/v2g_net.c (host-tested test_v2g_net.c, 89 checks)
and wired into ccs2.c/main.c. Communication only — NO power-stage GPIO. The heavy third-party
stacks (lwIP TCP reliability: SYN/ACK/retransmit/congestion; mbedTLS crypto: ECDHE/AES/SHA256/X509)
are NOT reimplemented bare-metal — they are represented by hooks, exactly as the stock RTOS is
represented by the bare-metal single loop. The replica reproduces the adapter's transport GLUE +
the byte-level wire framing + the protocol decisions (addressing, demux, deframe, TLS decision,
mode mapping, timers, EXI dispatch).

(G) IPv6/UDP/TCP WIRE FRAMING + DEMUX (lwIP raw-API plumbing):
  link-local addr  netif_create_ip6_linklocal_address 0x08090D68 : fe80::/64 + modified-EUI-64 from
    the QCA7005 PIB MAC. addr[0]=0x000080fe (LE fe80::); IID=[hw0^2,hw1,hw2,FF,FE,hw3,hw4,hw5] via
    htonl. netif 0x20020690 size 0xA4; input@+0x80=0x0809098A, linkoutput@+0x88=0x08093186,
    output_ip6@+0x8c=0x0809B35C. ethernetif_init 0x08093202 (from_mac=1 -> hwaddr=PIB MAC).
  RX demux         QCA dispatch 0x0808938A -> cb 0x08060866 -> low_level_input 0x080931A6
    (ETH_PAD_SIZE=2) -> netif->input -> ethernet_input 0x0809D914 (EtherType read ldrh LE,
    byte-swapped: IPv4 cmp#8, ARP cmp#0x608, IPv6 cmp#0xDD86) -> ip6_input 0x0809B88E (version==6;
    next-header demux @0x0809BB2C: 6->tcp_input 0x08099BA6, 17->udp_input 0x0809002C,
    58->icmp6_input 0x0809B3D0, 59->drop).
  TX framing       ip6_output_if 0x0809BBEC (40B hdr: vtf=htonl(0x60000000), plen BE@4, nexth@6,
    hoplim@7, src@8, dst@24) -> ethip6_output 0x0809B35C (mcast MAC 33:33:dst[12..15]; ND6
    0x0809D5D6 gated) -> ethernet_output 0x0809D9E4 -> low_level_output 0x08093186 -> QCA write
    0x08093DA8. udp_sendto_if_src 0x0809028A (UDP hdr src@0/dst@2/len@4/chksum@6 +
    inet_chksum_pseudo proto 17). tcp_output_segment 0x08092A6E (seq=htonl(snd_nxt)@4,
    ack@8, data-offset@12, flags@13, window=htons(rcv_wnd)@14, chksum proto 6). inet_chksum
    0x08098CAC (one's-complement fold). Ephemeral UDP src port = STM32 HW RNG (0x50060800) ring,
    ubfx(rand,0,14)+0xC000 (NOT an LCG); state1 @0x08020526.
  TCP pcb          snd_buf@+0x80, snd_queuelen@+0x82 (max 40), snd_nxt@+0x44, rcv_wnd@+0x4a,
    mss@+0x52 (536). recv_cb@+0xa0=0x08060A82 (pbuf deref + tcp_recved), sent_cb@+0x9c=0x08060A38
    (sem post 0x200003C8). Setters: recv 0x080922CE str[+0xa0], sent 0x080922D8 str[+0x9c],
    err 0x080922E2 str[+0xac], poll 0x080922FC str[+0xa8]. connected-cb 0x08060ACE registers
    poll cb 0x08060A58 (interval 1) / recv 0x08060A82 / sent 0x08060A38, idle reset, event notify(1).
    poll idle>=300 (0x12c) -> tcp_close. tcp_write 0x0809263C (COPY bit0), tcp_output 0x08092B60.
    Write primitive 0x08060B44 = mutex + tcp_write(COPY) + tcp_output.

(H) TLS DECISION + mbedTLS CONFIG + STREAM CARRIAGE:
  LOAD-BEARING WIRE CORRECTION: ISO15118-2/DIN70121 SDP security byte 0x00=TLS, 0x10=No-TLS.
    TLS decision state4 0x080207BC: ldrb r0,[r4,#0x23]; cbz r0 -> 0x080207F0 (TLS branch, log
    "TLS : Connecting", state+=2 -> state6 mbedTLS setup); byte!=0 -> mode1 plain (state+=1 ->
    state5). So TLS iff SECC security byte==0 — the firmware CODE is CORRECT. The INVERTED items
    were: the firmware log labels, the prior sdp_security_trigger memory "0x10=TLS" label, and the
    prior sdp.c replica use_tls=(!=0). Request builder 0x080204FA: count==0 -> 0x10 (No-TLS, no
    root certs); count>0 -> 0x00 (TLS). Response copy 0x080205F2/F4 buf[0x1a] -> ctx+0x23 verbatim.
    mode1=PLAIN (raw tcp_write), mode2=TLS (ssl_write) — the prior brief/report C had it backwards.
  mbedTLS setup    0x080604D2(cert_list,flag=0): ssl_init (memset 0xDC) -> ssl_config_init (0x78) ->
    x509_crt_init (0x134) -> <=5 x x509_crt_parse -> config_defaults(client) -> conf_authmode
    (2=VERIFY_REQUIRED, bfi bits[3:2]) -> conf_ca_chain -> conf_rng (cb 0x08060497) -> ssl_setup ->
    ssl_set_bio (f_send 0x0806043E / f_recv 0x08060414) -> ssl_set_timer_cb. Cipher list 0x080B0668
    = {0xC023 ECDHE-ECDSA-AES128-CBC-SHA256, 0xC025 ECDH-ECDSA-AES128-CBC-SHA256, 0} (exactly 2;
    the "5" is the CA-cert loop bound). Cert source RAM 0x20018A48 (getter 0x08051ADC), flash PnC
    partition 0x001F8010.
  stream ctx       0x20020314 IS mbedtls_ssl_context (220B/0xDC); the 2x8509B (0x213D) buffers are
    the TLS in_buf/out_buf, NOT a V2GTP ring. [ctx+0xa0]=out_msg. ssl_write 0x0808F950 ->
    write_real 0x0808E94A (5B record header + encrypt) -> flush 0x0808E8D8 blx f_send -> tcp_write.
    ssl_read 0x0808F818 -> fetch_input 0x0808EB40. handshake_step 0x0808F78E, handshake-progress
    0x0806058C (timeout 5000).
  EXI ring         0x20001FEC = diagnostic TRACE buffer (16x128B, idx byte 0x200003B9 &0xf, 4B LE
    RTOS-tick prefix + <=124B frame), fed by dispatch (RX) + send router (TX), drained ONLY at
    shutdown state 0xf4 (log dump). The live RX path BYPASSES the ring. Feed 0x08020194.
  live RX path     dispatch 0x08020224 (v2gtp_parse 0x080212C2 type 0x180=0x8001 EXI, framelen=
    rev([buf+4])+8) -> session-rx entry 0x0802E76A (flag+sem) -> session task -> session RX engine
    0x080353B2 -> decode wrapper 0x08033C24 (cap 0x100, buf 0x200031D0, strips 8B V2GTP) -> root
    decoder 0x0806997A (= ccs2_rx_exi -> exi_decode_header -> din_session_rx).
  send router      0x08020338: mode=[ctx 0x20000BBC+0x29]; 1->fnA 0x08020328->tcp_write 0x08060B44;
    2->fnB 0x08060682->ssl_write 0x0808F950. Loop-until-all-sent cap 0x1388=5000ms, budget
    0xc350=50000ms, blocks on sent-sem. Send entry 0x0802104A TX-pending 0x20002A54
    {ts,timeout,buf,len,flag} -6 if pending, cooldown 0xB4=180ms. Time base ms (TIM7 PSC83/ARR999
    -> 1ms, accessor 0x0808A236 reads [0x20000A54]).
  transport SM     states: 3 UDP close + TCP connect (timer 30000); 4 TLS decision; 5 plain rx;
    6 TLS setup; 7 handshake; 8 mode2; 9 ssl_read wrapper 0x08060636; 0xf0 flush; 0xf1 fail;
    0xf4 shutdown.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze94.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f): return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
def pool(o):
    h = u16(o)
    if (h & 0xF800) == 0x4800:
        p = (((rt(o)+4) & ~3) - TB) + (h & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    if (h & 0xFF7F) == 0xF85F and o+4 <= N:
        U = (h >> 7) & 1; imm = u16(o+2) & 0xFFF; b = ((rt(o)+4) & ~3)
        p = (b+imm if U else b-imm) - TB
        if 0 <= p and p+4 <= N: return u32(p)
    return None

def dump(addr, n, label, stop=True):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = ""
        if w is not None:
            tag = (" FLASH" if 0x08000000 <= w < 0x08100000 else
                   " RAM" if 0x20000000 <= w < 0x20030000 else
                   " PERIPH" if 0x40000000 <= w < 0x40100000 else "")
            ex = f"  ; =0x{w:08X}{tag}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:9s} {i.op_str}{ex}")
        a += i.size
        if stop and i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if stop and i.mnemonic == 'pop' and 'pc' in i.op_str: break

checks = failures = 0
def check(cond, msg):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1
        print("FAIL:", msg)

print("################ LIVE UDP/TCP/IPv6 + mbedTLS TRANSPORT (§5.9, byte-exact, C013) ################")

print("\n#### (G) IPv6 link-local addressing + netif ####")
dump(0x08090D68, 40, "netif_create_ip6_linklocal_address 0x08090D68 (fe80:: + EUI-64 IID hw0^2)", stop=False)
dump(0x08093202, 30, "ethernetif_init 0x08093202 (from_mac=1 -> netif hwaddr = PIB MAC)", stop=False)

print("\n#### (G) RX demux: Ethernet -> IPv6 -> UDP/TCP ####")
dump(0x0809D914, 40, "ethernet_input 0x0809D914 (EtherType ldrh LE: IPv4 #8 / ARP #0x608 / IPv6 #0xDD86)", stop=False)
dump(0x0809B88E, 30, "ip6_input 0x0809B88E (version==6 check)", stop=False)
dump(0x0809BB2C, 24, "ip6 next-header demux 0x0809BB2C (6 TCP / 17 UDP / 58 ICMPv6 / 59 drop)", stop=False)
dump(0x080931A6, 24, "low_level_input 0x080931A6 (ETH_PAD_SIZE=2 pbuf offset)", stop=False)

print("\n#### (G) TX framing: IPv6 header + UDP/TCP + checksum ####")
dump(0x0809BBEC, 40, "ip6_output_if 0x0809BBEC (vtf=htonl(0x60000000), plen BE, nexth@6, hop@7, src@8, dst@24)", stop=False)
dump(0x0809B35C, 30, "ethip6_output 0x0809B35C (mcast MAC 33:33:dst[12..15]; ND6 gated)", stop=False)
dump(0x0809028A, 30, "udp_sendto_if_src 0x0809028A (UDP hdr + inet_chksum_pseudo proto 17)", stop=False)
dump(0x08092A6E, 36, "tcp_output_segment 0x08092A6E (seq=htonl(snd_nxt), window=htons(rcv_wnd), chksum proto 6)", stop=False)
dump(0x08098CAC, 24, "inet_chksum 0x08098CAC (one's-complement 16-bit sum + fold)", stop=False)

print("\n#### (G) TCP pcb callbacks + write primitive ####")
dump(0x08060ACE, 30, "connected-cb 0x08060ACE (register poll/recv/sent cb, idle reset, event notify(1))", stop=False)
dump(0x08060A58, 24, "poll cb 0x08060A58 (interval 1; idle >= 300 (0x12c) -> tcp_close)", stop=False)
dump(0x08060A82, 20, "recv cb 0x08060A82 (pbuf deref + tcp_recved) @pcb+0xa0", stop=False)
dump(0x08060A38, 16, "sent cb 0x08060A38 (sem post 0x200003C8) @pcb+0x9c", stop=False)
dump(0x08060B44, 24, "TCP write primitive 0x08060B44 (mutex + tcp_write(COPY) + tcp_output)", stop=False)

print("\n#### (H) LOAD-BEARING TLS DECISION (state4) — TLS iff SECC security byte == 0 ####")
dump(0x080207BC, 24, "TLS decision 0x080207BC (ldrb [r4,#0x23]; cbz -> TLS branch state6; else mode1 plain)", stop=False)
dump(0x080204FA, 24, "security select 0x080204FA (cert-count low-byte==0 -> 0x10 No-TLS else 0x00 TLS)", stop=False)
# verify the cbz-on-zero decision byte
ins = dis(0x080207BC - TB, 6)
mn = [i.mnemonic.split('.')[0] for i in ins]
check('ldrb' in mn and 'cbz' in mn, "TLS decision 0x080207BC is ldrb + cbz (TLS iff byte==0)")

print("\n#### (H) mbedTLS setup + cipher list ####")
dump(0x080604D2, 50, "mbedTLS setup 0x080604D2 (ssl_init 0xDC / config 0x78 / authmode 2 / ca_chain / bio)", stop=False)
dump(0x080B0668, 6, "cipher list 0x080B0668 ({0xC023, 0xC025, 0})", stop=False)
# cipher list stored as 32-bit ints {0xC023, 0xC025, 0}
c0, c1, c2 = u32(0x080B0668 - TB), u32(0x080B0668 - TB + 4), u32(0x080B0668 - TB + 8)
print(f"  cipher words: 0x{c0:08X} 0x{c1:08X} 0x{c2:08X}")
check(c0 == 0xC023 and c1 == 0xC025 and c2 == 0,
      "cipher list = {0xC023 ECDHE-ECDSA-AES128-CBC-SHA256, 0xC025 ECDH-ECDSA-AES128-CBC-SHA256, 0}")

print("\n#### (H) TLS record wrap + stream ctx ####")
dump(0x0808F950, 24, "ssl_write 0x0808F950 (-> write_real 0x0808E94A)", stop=False)
dump(0x0808E94A, 30, "ssl_write_real 0x0808E94A (5B record header + encrypt -> flush 0x0808E8D8)", stop=False)
dump(0x0808F818, 24, "ssl_read 0x0808F818 (-> fetch_input 0x0808EB40)", stop=False)
dump(0x0806058C, 24, "handshake-progress 0x0806058C (timeout 5000)", stop=False)

print("\n#### (H) send router + EXI dispatch + trace ring ####")
dump(0x08020338, 36, "send router 0x08020338 (mode=[ctx+0x29]: 1 plain tcp_write / 2 TLS ssl_write; cap 5000/budget 50000)", stop=False)
dump(0x0802104A, 30, "send entry 0x0802104A (TX-pending 0x20002A54, -6 if pending, cooldown 180ms)", stop=False)
dump(0x08020224, 36, "EXI dispatch 0x08020224 (v2gtp_parse type 0x8001, framelen=rev([buf+4])+8 -> session-rx)", stop=False)
dump(0x08020194, 28, "trace-ring feed 0x08020194 (16x128B, idx&0xf, 4B LE tick + <=124B frame)", stop=False)

print("\n== RESOLVED live transport (C013) ==")
print("  (G) IPv6 link-local fe80::/64 + modified-EUI-64 from PIB MAC (netif_create_ip6_linklocal_address")
print("      0x08090D68). RX: QCA -> low_level_input -> ethernet_input 0x0809D914 (EtherType LE")
print("      0xDD86 IPv6) -> ip6_input 0x0809B88E (next-header 6 TCP / 17 UDP / 58 ICMPv6 / 59 drop).")
print("      TX: ip6_output_if 0x0809BBEC (40B hdr) -> ethip6_output 0x0809B35C (mcast 33:33) ->")
print("      low_level_output -> QCA write. UDP udp_sendto_if_src 0x0809028A / TCP tcp_output_segment")
print("      0x08092A6E + inet_chksum_pseudo. TCP pcb recv_cb@+0xa0 / sent_cb@+0x9c; poll idle>=300")
print("      -> close; write primitive 0x08060B44 = mutex+tcp_write(COPY)+tcp_output.")
print("  (H) TLS decision state4 0x080207BC: TLS iff SECC security byte==0 (cbz -> mbedTLS setup).")
print("      WIRE CORRECTION: 0x00=TLS / 0x10=No-TLS (the firmware code is correct; the log labels +")
print("      prior sdp.c use_tls(!=0) + sdp_security_trigger memory were inverted). mode1=PLAIN /")
print("      mode2=TLS. mbedTLS setup 0x080604D2: ssl ctx 0x20020314 (220B), 2x8509B record buffers,")
print("      cipher list 0x080B0668={0xC023,0xC025,0}, authmode 2 VERIFY_REQUIRED, CA from PnC store.")
print("      ssl_write 0x0808F950 -> write_real 0x0808E94A (5B record hdr+encrypt) -> f_send ->")
print("      tcp_write. EXI ring 0x20001FEC = diagnostic TRACE (16x128B), live RX BYPASSES it.")
print("      Live RX: dispatch 0x08020224 -> session-rx 0x0802E76A -> RX engine 0x080353B2 -> decode")
print("      wrapper 0x08033C24 (=ccs2_rx_exi). Send router 0x08020338 (cap 5000/budget 50000ms,")
print("      cooldown 180ms). Transport SM states 3..9 + 0xf0/0xf1/0xf4.")
print("  Replicated INERT in custom_fw/src/v2g_net.c + wired into ccs2.c/main.c; communication only,")
print("      NO power GPIO. Host-tested (test_v2g_net 89); built-image power-GPIO safety + cipher")
print("      list + EtherType/next-header demux disasm-verified (custom_fw/verify_ccs2.py, 56 checks).")
print("      Power-stage drive stays GATED.")
print("  GATED (third-party stacks, represented by hooks): lwIP TCP reliability (SYN/ACK/retransmit/")
print("      congestion), mbedTLS crypto (ECDHE/AES/SHA256/X509), ND6 neighbor resolution, CA")
print("      flash->RAM populator, SECC-peer wire convention capture [?].")

print(f"\n{checks} checks, {failures} failures")
import sys
sys.exit(1 if failures else 0)
