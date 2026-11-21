#!/usr/bin/env python3
"""analyze97.py — stock stack library identification + recovered-config mapping (REPORT §5.9).

Grounds the custom_fw "mbedTLS + lwIP (full)" library pivot in the C013 firmware bytes: the stock
CCS2 network stack IS lwIP 2.1.x (IPv6/ND6/TCP/UDP — the nd6_input/nd6_tmr/ethernet_input/
ip6_input symbols recovered in analyze96 ARE lwIP) + Mbed-TLS 2.28 (TLS 1.2 CLIENT-only). This
decoder (A) re-confirms the mbedTLS ssl_setup API call sequence + the recovered ciphersuite list
+ the VERIFY_REQUIRED authmode mapping from the bytes, and (B) asserts the vendored
custom_fw/src/mbedtls_config.h + lwipopts.h reproduce the recovered config values, so the
libraries are configured byte-faithfully rather than re-implemented from scratch.

=============================================================================================
(A) mbedTLS ssl_setup identification (C013 setup fn 0x080604D2; caller 0x080208CA, analyze96).
=============================================================================================
  ssl ctx     0x20020314 ; ssl_config 0x200203F0 (= 0x20020468 - 0x78) ; ca_chain 0x20020468.
  API seq     0x080604E6 bl 0x0808F322 mbedtls_ssl_init(ssl)
              0x080604EE bl 0x0808FAD0 mbedtls_ssl_config_init(conf)   [r0 = 0x20020468-0x78]
              0x080604F4 bl 0x0805D6F8 mbedtls_x509_crt_init(ca_chain) [r0 = 0x20020468]
              Root loop 0x080604FC: cbz r6 / ldm r6!,{r1} / cbz r1 / ldm r1!,{r2} /
                0x08060506 bl 0x0805D76C mbedtls_x509_crt_parse(ca_chain, der_len+DER) /
                cmp r7,#5 @0x08060510 / blt 0x080604FC @0x08060512  (<=5 roots, NULL-term ptr-array)
              0x08060514 cbz r7 -> skip ca_chain when no roots parsed
              0x08060520 bl 0x0808FAD6 mbedtls_ssl_conf_ca_chain(conf, ca_chain, NULL)
              0x08060534 bl 0x0808F442 mbedtls_ssl_conf_authmode(conf, mode)
              0x08060540 bl 0x0808F504 mbedtls_ssl_conf_rng(conf, f_rng, p_rng)
  authmode    0x08060528 cmp.w r8,#0 (arg1 = security mode) / beq 0x08060568 ;
              0x08060568 movs r1,#2 (MBEDTLS_SSL_VERIFY_REQUIRED) / b 0x08060530 ;
              else 0x0806052E movs r1,#1 (MBEDTLS_SSL_VERIFY_OPTIONAL). arg1==0 (TLS) -> REQUIRED.
  ciphers     int[] @0x080B0668 = {0xC023 ECDHE-ECDSA-AES128-CBC-SHA256,
              0xC025 ECDH-ECDSA-AES128-CBC-SHA256, 0x0000 terminator} (32-bit words, mbedTLS int[]).
  RNG         stock f_rng = STM32 HW-RNG 0x50060800 (NOT ctr_drbg) -> entropy/DRBG modules OFF,
              custom f_rng wired by glue (hw_rng.c). [Agent M / analyze95]

=============================================================================================
(B) recovered-config -> vendored-config mapping (custom_fw/src/mbedtls_config.h + lwipopts.h).
=============================================================================================
  mbedTLS     CLIENT-only (SSL_CLI_C, NO SSL_SRV_C) / TLS1_2 / EtM (bit9) + EMS (bit10) /
              IN=OUT=MAX_CONTENT_LEN 8192 (recovered 0x2000) / ECDHE_ECDSA(0xC023)+ECDH_ECDSA(0xC025) /
              secp256r1 ONLY / AES-CBC+PKCS7+ROM tables / SHA256(+224)+MD5 (NO SHA1/SHA512) /
              ECDH+ECDSA+BIGNUM / X509 DER parse (NO PEM/BASE64) / MEMORY_BUFFER_ALLOC_C static heap /
              NO_PLATFORM_ENTROPY+NO_DEFAULT_ENTROPY_SOURCES / NO RSA/GCM.
  lwIP        NO_SYS 1 raw API / IPv6-only (IPV4 0) / TCP+UDP+ICMP6 / ETHERNET 1 ARP 0 /
              IPV6_FRAG+REASS 1 (EXI > MTU) / TCP_MSS 1460 WND 11680 SND_BUF 14600(10*MSS)
              SND_QUEUELEN 40 SYNMAXRTX 3 MAXRTX 4 TMR_INTERVAL 250 MSL 60000 /
              ND6 REACHABLE_TIME 30000 RETRANS_TIMER 1000 NUM_NEIGHBORS 8 / SUPPORT_CUSTOM_PBUF 1 /
              MEM_LIBC_MALLOC 0 (static pools). [Agent K/N / analyze95/96]

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze97.py'
"""
import re
import sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True

def u16(o): return int.from_bytes(fw[o:o+2], 'little')
def u32a(a):
    o = a - TB
    return int.from_bytes(fw[o:o+4], 'little') if 0 <= o <= N-4 else None
def dis(a, n):
    o = a - TB
    return list(md.disasm(fw[o:o+n*4], a))
def pool(ins):
    h = int.from_bytes(ins.bytes[:2], 'little')
    if (h & 0xF800) == 0x4800:
        p = ((ins.address + 4) & ~3) + (h & 0xFF)*4; return u32a(p)
    if (h & 0xFF7F) == 0xF85F and len(ins.bytes) >= 4:
        u = (h >> 7) & 1; im = int.from_bytes(ins.bytes[2:4], 'little') & 0xFFF
        p = ((ins.address + 4) & ~3) + (im if u else -im); return u32a(p)
    return None
def bl_target(ins):
    # capstone already resolves the absolute Thumb BL target in the immediate operand
    if ins.mnemonic == 'bl' and ins.operands and ins.operands[0].type == 2:
        return ins.operands[0].imm & 0xFFFFFFFF
    return None
def find(a, n, mn=None, imm=None):
    for ins in dis(a, n):
        if mn and ins.mnemonic.split('.')[0] != mn: continue
        if imm is not None:
            if not any(op.type == 2 and (op.imm & 0xFFFFFFFF) == (imm & 0xFFFFFFFF)
                       for op in ins.operands): continue
        return ins
    return None
def bl_at(a):
    ins = dis(a, 1)[0]
    return bl_target(ins)
def dump(addr, n, label, stop=True):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    for ins in dis(addr, n):
        w = pool(ins); ex = ""
        if w is not None:
            tag = (" FLASH" if 0x08000000 <= w < 0x08100000 else
                   " RAM" if 0x20000000 <= w < 0x20030000 else
                   " PERIPH" if 0x40000000 <= w < 0x40100000 else "")
            ex = f"  ; =0x{w:08X}{tag}"
        bt = bl_target(ins)
        if bt is not None: ex += f"  -> bl 0x{bt:08X}"
        print(f"  0x{ins.address:08X}: {ins.mnemonic:9s} {ins.op_str}{ex}")
        if stop and ins.mnemonic == 'bx' and 'lr' in ins.op_str: break
        if stop and ins.mnemonic == 'pop' and 'pc' in ins.op_str: break

checks = failures = 0
def check(cond, msg):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1; print("FAIL:", msg)

print("######## STOCK STACK = lwIP 2.1.x + mbedTLS 2.28 CLIENT (§5.9, C013 byte-grounded) ########")

# =============================================================================================
# (A1) recovered ciphersuite list — mbedTLS int[] (32-bit words), NULL-terminated
# =============================================================================================
print("\n#### (A1) ciphersuite int[] @0x080B0668 = {0xC023, 0xC025, 0} ####")
c0, c1, c2 = u32a(0x080B0668), u32a(0x080B066C), u32a(0x080B0670)
print(f"  words = 0x{c0:08X}, 0x{c1:08X}, 0x{c2:08X}")
check(c0 == 0xC023, "cipher[0] == 0xC023 (ECDHE-ECDSA-AES128-CBC-SHA256)")
check(c1 == 0xC025, "cipher[1] == 0xC025 (ECDH-ECDSA-AES128-CBC-SHA256)")
check(c2 == 0x0000, "cipher[2] == 0 (mbedTLS int[] NULL terminator)")

# =============================================================================================
# (A2) mbedTLS ssl_setup API call sequence (setup fn 0x080604D2)
# =============================================================================================
print("\n#### (A2) ssl_setup 0x080604D2 — ssl_init / config_init / x509_crt_init ####")
dump(0x080604D2, 12, "ssl_setup entry 0x080604D2", stop=False)
pools = [pool(ins) for ins in dis(0x080604D2, 12)]
check(0x20020314 in pools, "ssl ctx pool 0x20020314")
check(0x20020468 in pools, "ca_chain / conf-base pool 0x20020468 (conf = base-0x78 = 0x200203F0)")
check(bl_at(0x080604E6) == 0x0808F322, "bl mbedtls_ssl_init 0x0808F322 @0x080604E6")
check(bl_at(0x080604EE) == 0x0808FAD0, "bl mbedtls_ssl_config_init 0x0808FAD0 @0x080604EE")
check(bl_at(0x080604F4) == 0x0805D6F8, "bl mbedtls_x509_crt_init 0x0805D6F8 @0x080604F4")
ins = dis(0x080604EC, 1)[0]
check(ins.mnemonic.startswith('subs') and '#0x78' in ins.op_str,
      "conf = 0x20020468 - 0x78 (subs r0,#0x78) @0x080604EC")

print("\n#### (A2) Root-cert parse loop (ldm ptr-array / x509_crt_parse / <=5) ####")
dump(0x080604FC, 10, "Root loop 0x080604FC", stop=False)
ins = dis(0x080604FE, 1)[0]
check(ins.mnemonic.startswith('ldm') and 'r6!' in ins.op_str,
      "ldm r6!,{r1} (next root ptr) @0x080604FE")
check(find(0x08060500, 1, 'cbz') is not None, "cbz r1 (NULL-term ptr-array end) @0x08060500")
ins = dis(0x08060502, 1)[0]
check(ins.mnemonic.startswith('ldm') and 'r1!' in ins.op_str,
      "ldm r1!,{r2} (der_len+DER) @0x08060502")
check(bl_at(0x08060506) == 0x0805D76C, "bl mbedtls_x509_crt_parse 0x0805D76C @0x08060506")
check(find(0x08060510, 1, 'cmp', 5) is not None, "cmp r7,#5 (<=5 roots) @0x08060510")
ins = dis(0x08060512, 1)[0]
check(ins.mnemonic.startswith('blt'), "blt -> loop top 0x080604FC @0x08060512")

print("\n#### (A2) ssl_conf_ca_chain (gated on roots parsed) + conf_rng ####")
dump(0x08060514, 12, "ca_chain + authmode + rng 0x08060514", stop=False)
check(find(0x08060514, 1, 'cbz') is not None, "cbz r7 -> skip ca_chain when no roots @0x08060514")
check(bl_at(0x08060520) == 0x0808FAD6, "bl mbedtls_ssl_conf_ca_chain 0x0808FAD6 @0x08060520")
check(bl_at(0x08060534) == 0x0808F442, "bl mbedtls_ssl_conf_authmode 0x0808F442 @0x08060534")
check(bl_at(0x08060540) == 0x0808F504, "bl mbedtls_ssl_conf_rng 0x0808F504 @0x08060540")

# =============================================================================================
# (A3) authmode mapping — arg1(security)==0 -> VERIFY_REQUIRED(2), else VERIFY_OPTIONAL(1)
# =============================================================================================
print("\n#### (A3) authmode mapping 0x08060528 / 0x08060568 (arg1==0 -> 2 REQUIRED) ####")
dump(0x08060528, 4, "authmode arg1 test 0x08060528", stop=False)
ins = dis(0x08060528, 1)[0]
check(ins.mnemonic.startswith('cmp') and '#0' in ins.op_str, "cmp.w r8,#0 (arg1 security) @0x08060528")
ins = dis(0x0806052C, 1)[0]
check(ins.mnemonic.startswith('beq'), "beq -> REQUIRED branch 0x08060568 @0x0806052C")
i = find(0x0806052E, 2, 'movs', 1)
check(i is not None and i.address == 0x0806052E, "movs r1,#1 (VERIFY_OPTIONAL) @0x0806052E")
dump(0x08060568, 2, "REQUIRED branch 0x08060568", stop=False)
i = find(0x08060568, 2, 'movs', 2)
check(i is not None and i.address == 0x08060568, "movs r1,#2 (VERIFY_REQUIRED) @0x08060568")

print("\n== RESOLVED stock TLS stack identification (C013) ==")
print("  ssl_setup 0x080604D2 calls the mbedTLS 2.28 client API in order: ssl_init 0x0808F322 /")
print("  ssl_config_init 0x0808FAD0 / x509_crt_init 0x0805D6F8 / x509_crt_parse 0x0805D76C (Root")
print("  loop <=5, NULL-term ptr-array) / ssl_conf_ca_chain 0x0808FAD6 / ssl_conf_authmode 0x0808F442 /")
print("  ssl_conf_rng 0x0808F504. Ciphersuite int[] @0x080B0668 = {0xC023, 0xC025, 0}. authmode")
print("  arg1(security)==0 -> VERIFY_REQUIRED(2) @0x08060568 else OPTIONAL(1) @0x0806052E. The")
print("  IPv6/ND6/TCP layer is lwIP 2.1.x (analyze96 nd6_input/nd6_tmr/ethernet_input symbols).")
print("  => stock stack IS lwIP + mbedTLS; custom_fw vendors both, configured byte-faithfully below.")

# =============================================================================================
# (B) recovered-config -> vendored-config mapping
# =============================================================================================
def read_cfg(path):
    txt = open(path, encoding='utf-8').read()
    defs = {}
    for line in txt.splitlines():           # per-line: \s must not cross newlines (bare #defines)
        m = re.match(r'\s*#define\s+(\w+)(.*)$', line)
        if not m: continue
        name = m.group(1)
        val = re.sub(r'/\*.*?\*/', '', m.group(2)).strip()   # strip trailing block comments
        defs[name] = val
    return txt, defs

print("\n#### (B1) vendored mbedtls_config.h reproduces recovered TLS/crypto config ####")
mtxt, mdefs = read_cfg('custom_fw/src/mbedtls_config.h')
def has(d, k): return k in d
def val(d, k): return d.get(k, '')
# client-only TLS 1.2 + EtM/EMS + 8192 content
check(has(mdefs, 'MBEDTLS_SSL_CLI_C'), "MBEDTLS_SSL_CLI_C present (client)")
check(not has(mdefs, 'MBEDTLS_SSL_SRV_C'), "MBEDTLS_SSL_SRV_C ABSENT (stock is EVCC client-only)")
check(has(mdefs, 'MBEDTLS_SSL_PROTO_TLS1_2'), "MBEDTLS_SSL_PROTO_TLS1_2 present")
check(has(mdefs, 'MBEDTLS_SSL_ENCRYPT_THEN_MAC'), "EtM present (recovered config bit9)")
check(has(mdefs, 'MBEDTLS_SSL_EXTENDED_MASTER_SECRET'), "EMS present (recovered config bit10)")
check(val(mdefs, 'MBEDTLS_SSL_MAX_CONTENT_LEN') == '8192', "SSL_MAX_CONTENT_LEN 8192 (recovered 0x2000)")
check(val(mdefs, 'MBEDTLS_SSL_IN_CONTENT_LEN') == '8192', "SSL_IN_CONTENT_LEN 8192")
check(val(mdefs, 'MBEDTLS_SSL_OUT_CONTENT_LEN') == '8192', "SSL_OUT_CONTENT_LEN 8192")
# the two recovered ECDSA suites + secp256r1 only
check(has(mdefs, 'MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED'), "ECDHE_ECDSA enabled (0xC023)")
check(has(mdefs, 'MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED'), "ECDH_ECDSA enabled (0xC025)")
check(has(mdefs, 'MBEDTLS_ECP_DP_SECP256R1_ENABLED'), "secp256r1 enabled")
check(not has(mdefs, 'MBEDTLS_ECP_DP_SECP384R1_ENABLED'), "secp384r1 ABSENT (secp256r1 ONLY)")
# AES-CBC + PKCS7 + ROM tables; SHA256/224 + MD5, no SHA1/SHA512
check(has(mdefs, 'MBEDTLS_AES_C') and has(mdefs, 'MBEDTLS_AES_ROM_TABLES'), "AES_C + AES_ROM_TABLES")
check(has(mdefs, 'MBEDTLS_CIPHER_MODE_CBC') and has(mdefs, 'MBEDTLS_CIPHER_PADDING_PKCS7'),
      "CIPHER_MODE_CBC + CIPHER_PADDING_PKCS7")
check(has(mdefs, 'MBEDTLS_SHA256_C') and has(mdefs, 'MBEDTLS_MD5_C'), "SHA256_C + MD5_C (sig_hashes {6,5,3})")
check(not has(mdefs, 'MBEDTLS_SHA1_C'), "SHA1_C ABSENT (recovered sig_hashes exclude SHA1)")
check(not has(mdefs, 'MBEDTLS_SHA512_C'), "SHA512_C ABSENT")
# ECC + X509 DER (no PEM/base64) + static heap + HW-RNG (no entropy/DRBG)
check(has(mdefs, 'MBEDTLS_ECDH_C') and has(mdefs, 'MBEDTLS_ECDSA_C') and has(mdefs, 'MBEDTLS_BIGNUM_C'),
      "ECDH_C + ECDSA_C + BIGNUM_C")
check(has(mdefs, 'MBEDTLS_X509_CRT_PARSE_C') and has(mdefs, 'MBEDTLS_PK_PARSE_C'),
      "X509_CRT_PARSE_C + PK_PARSE_C (DER chain verify)")
check(not has(mdefs, 'MBEDTLS_PEM_PARSE_C') and not has(mdefs, 'MBEDTLS_BASE64_C'),
      "PEM_PARSE_C + BASE64_C ABSENT (CA store is DER)")
check(has(mdefs, 'MBEDTLS_MEMORY_BUFFER_ALLOC_C'), "MEMORY_BUFFER_ALLOC_C (static-pool heap)")
check(has(mdefs, 'MBEDTLS_NO_PLATFORM_ENTROPY') and has(mdefs, 'MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES'),
      "NO_PLATFORM_ENTROPY + NO_DEFAULT_ENTROPY_SOURCES (HW-RNG f_rng, not ctr_drbg)")
check(not has(mdefs, 'MBEDTLS_RSA_C') and not has(mdefs, 'MBEDTLS_GCM_C'), "RSA_C + GCM_C ABSENT")

print("\n#### (B2) vendored lwipopts.h reproduces recovered TCP/IPv6/ND6 config ####")
ltxt, ldefs = read_cfg('custom_fw/src/lwipopts.h')
check(val(ldefs, 'NO_SYS') == '1', "NO_SYS 1 (bare-metal raw API)")
check(val(ldefs, 'LWIP_IPV4') == '0' and val(ldefs, 'LWIP_IPV6') == '1', "IPv6-only (IPV4 0 / IPV6 1)")
check(val(ldefs, 'LWIP_TCP') == '1' and val(ldefs, 'LWIP_UDP') == '1' and val(ldefs, 'LWIP_ICMP6') == '1',
      "TCP + UDP + ICMP6 enabled")
check(val(ldefs, 'LWIP_ETHERNET') == '1' and val(ldefs, 'LWIP_ARP') == '0', "ETHERNET 1 / ARP 0 (IPv6)")
check(val(ldefs, 'LWIP_IPV6_FRAG') == '1' and val(ldefs, 'LWIP_IPV6_REASS') == '1',
      "IPV6_FRAG + REASS 1 (EXI frames > MTU)")
check(val(ldefs, 'TCP_MSS') == '1460', "TCP_MSS 1460 (0x5b4)")
check(val(ldefs, 'TCP_WND') == '11680', "TCP_WND 11680 (0x2da0)")
check(val(ldefs, 'TCP_SND_BUF') == '14600', "TCP_SND_BUF 14600 (0x3908 = 10*MSS)")
check(val(ldefs, 'TCP_SND_QUEUELEN') == '40', "TCP_SND_QUEUELEN 40 (0x28)")
check(val(ldefs, 'TCP_SYNMAXRTX') == '3' and val(ldefs, 'TCP_MAXRTX') == '4', "SYNMAXRTX 3 / MAXRTX 4")
check(val(ldefs, 'TCP_TMR_INTERVAL') == '250', "TCP_TMR_INTERVAL 250 (fasttmr 250ms)")
check(val(ldefs, 'TCP_MSL') == '60000', "TCP_MSL 60000 (TIME_WAIT 2*MSL = 120s)")
check(val(ldefs, 'LWIP_ND6_REACHABLE_TIME') == '30000', "ND6_REACHABLE_TIME 30000")
check(val(ldefs, 'LWIP_ND6_RETRANS_TIMER') == '1000', "ND6_RETRANS_TIMER 1000")
check(val(ldefs, 'LWIP_ND6_NUM_NEIGHBORS') == '8', "ND6_NUM_NEIGHBORS 8")
check(val(ldefs, 'LWIP_SUPPORT_CUSTOM_PBUF') == '1', "SUPPORT_CUSTOM_PBUF 1 (IPv6 frag/reass)")
check(val(ldefs, 'MEM_LIBC_MALLOC') == '0', "MEM_LIBC_MALLOC 0 (static pools, no libc heap)")

print("\n== RESOLVED recovered-config mapping (custom_fw vendored libraries) ==")
print("  mbedtls_config.h: CLIENT-only TLS1.2 + EtM/EMS + 8192 content + {ECDHE_ECDSA 0xC023,")
print("  ECDH_ECDSA 0xC025} + secp256r1-only + AES-CBC/PKCS7/ROM + SHA256/MD5 (no SHA1/512) +")
print("  X509 DER (no PEM) + MEMORY_BUFFER_ALLOC_C + HW-RNG (no entropy/DRBG) + no RSA/GCM.")
print("  lwipopts.h: NO_SYS 1 IPv6-only TCP/UDP/ICMP6 + frag/reass + MSS1460/WND11680/SND_BUF14600/")
print("  QUEUELEN40/SYNMAXRTX3/MAXRTX4/TMR250/MSL60000 + ND6 30000/1000/8 + custom-pbuf + static pools.")
print("  => the vendored mbedTLS 2.28.9 + lwIP 2.1.4 are configured byte-faithfully to the recovered")
print("  C013 stack; recovered GLUE (v2g_net SM / V2GTP deframe / EXI dispatch / SDP / QCA7005 netif /")
print("  ca_store) wires into the library APIs. Power-stage drive stays GATED LAST (§5.21/§7).")

print(f"\n{checks} checks, {failures} failures")
sys.exit(1 if failures else 0)
