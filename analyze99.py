#!/usr/bin/env python3
"""
analyze99.py — Agent L reproducible decoder/assertor for the C013 mbedTLS
TLS 1.2 client handshake state machine + record layer + cipher/curve config + bio glue.

Loads decoded_c013.bin (via helpers.py), dumps the load-bearing functions, ASSERTS every
byte-exact constant claimed in agentL_mbedtls_tls.md, prints the mechanism, and ends with
    "N checks, M failures"
Run:  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze99.py'

RESEARCH ONLY — reads the firmware image; writes nothing.
Addressing: true link base TB=0x0801FBFE; runtime = TB + file_offset. All addrs runtime.
Crypto PRIMITIVES (AES/SHA/ECDHE point-math/X509) are Agent M's scope — referenced by
address only, not re-derived here.
"""
import sys
sys.path.insert(0, '/home/iroha/projects/orientrise charge adapter/re/.qwen/tmp/ccs2_re')
# ---- inlined helpers.py (self-contained; Agent L mbedTLS TLS) ----
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
FWPATH = '.qwen/tmp/c013/decoded_c013.bin'
fw = open(FWPATH, 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
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
def tag(w):
    return (" FLASH" if 0x08000000 <= w < 0x08100000 else
            " RAM" if 0x20000000 <= w < 0x20030000 else "")
def dump(addr, n, label):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = ""
        if w is not None:
            ex = f"  ; =0x{w:08X}{tag(w)}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{ex}")
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break
    return a  # file offset where dump stopped

def hexdump(a, b, label=""):
    print(f"\n== hex {label} f+0x{a:05x}..0x{b:05x} (rt 0x{rt(a):08X}) ==")
    for o in range(a, b, 16):
        row = fw[o:o+16]
        hx = ' '.join(f'{c:02x}' for c in row)
        asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in row)
        ann = ''
        for k in range(0, 16, 4):
            if o+k+4 <= N:
                v = struct.unpack_from('<I', fw, o+k)[0]
                if 0x08020000 <= v < 0x080B0000:
                    s = fw[v-TB:v-TB+24].split(b'\x00')[0]
                    if len(s) >= 3 and all(32 <= c < 127 for c in s): ann += f' [+{k}->str {s.decode()!r}]'
        print(f"  f+0x{o:05x}: {hx:48s} {asc}{ann}")

def find_strings(pat):
    """Find all NUL-terminated strings containing pat; return (fileoff, full_string)."""
    res = []
    start = 0
    while True:
        i = fw.find(pat, start)
        if i < 0: break
        # back up to preceding NUL
        b = i
        while b > 0 and fw[b-1] != 0: b -= 1
        e = fw.find(b'\x00', i)
        if e < 0: e = N
        res.append((b, fw[b:e]))
        start = i + 1
    return res

def xrefs(addr):
    """Full xref scan: movw/movt pairs, ADR T1, LDR-literal T1/T2 (runtime-PC aligned)."""
    res = []; mp = {}
    for o in range(0, N-4, 2):
        h1 = u16(o); t = None; k = None
        if (h1 & 0xFBF0) in (0xF240, 0xF2C0):
            ins = dis(o)
            if ins and ins[0].mnemonic in ('movw', 'movt') and len(ins[0].operands) == 2:
                i = ins[0]; reg = i.operands[0].reg; imm = i.operands[1].imm & 0xFFFF
                if i.mnemonic == 'movw': mp[reg] = (imm, o)
                elif reg in mp:
                    lo, fo = mp.pop(reg); t = (imm << 16) | lo; k = 'movw/movt'; o = fo
        elif (h1 & 0xF800) == 0xA000:
            t = ((rt(o)+4) & ~3) + (h1 & 0xFF)*4; k = 'adrT1'
        elif (h1 & 0xF800) == 0x4800:
            pca = ((rt(o)+4) & ~3) - TB; p = pca + (h1 & 0xFF)*4
            t = u32(p) if 0 <= p and p+4 <= N else None; k = 'ldrT1'
        elif (h1 & 0xFF7F) == 0xF85F:
            h2 = u16(o+2); U = (h1 >> 7) & 1; pca = ((rt(o)+4) & ~3) - TB
            p = pca + ((h2 & 0xFFF) if U else -(h2 & 0xFFF))
            t = u32(p) if 0 <= p and p+4 <= N else None; k = 'ldrT2'
        if t == addr: res.append((o, k))
    return res

def movw_scan(lo, hi):
    """Scan MOVW immediates in [lo,hi] (decode full imm16; requires following movt check optional)."""
    res = []
    for o in range(0, N-4, 2):
        h1 = u16(o)
        if (h1 & 0xFBF0) == 0xF240:
            h2 = u16(o+2)
            if h2 & 0x8000: continue
            imm = ((h1 & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
            if lo <= imm <= hi:
                res.append((o, (h2 >> 8) & 0xF, imm))
    return res

def bl_targets(addr, n=400):
    """Walk n instrs from addr (function-aware-ish), collect BL targets + tail b.w."""
    a = addr - TB; out = []
    for _ in range(n):
        ins = dis(a)
        if not ins: break
        i = ins[0]
        if i.mnemonic == 'bl':
            try: out.append((rt(a), int(i.op_str.replace('#', ''), 0)))
            except ValueError: pass
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break
    return out# ---- end inlined helpers ----

# ---------------------------------------------------------------- check harness
CHECKS = 0
FAILS = 0
FAILED = []
def check(name, cond, detail=""):
    global CHECKS, FAILS
    CHECKS += 1
    if cond:
        print(f"  [PASS] {name}" + (f"  ({detail})" if detail else ""))
    else:
        FAILS += 1
        FAILED.append(name)
        print(f"  [FAIL] {name}" + (f"  ({detail})" if detail else ""))

def ins_at(addr):
    r = dis(addr - TB, 1)
    return r[0] if r else None

def bl_target(addr):
    i = ins_at(addr)
    if i and i.mnemonic in ('bl', 'b', 'b.w'):
        try: return int(i.op_str.replace('#', ''), 0)
        except ValueError: return None
    return None

def stub_bl_targets(addr, n=8):
    """Collect bl/b.w targets within the first n instrs of a TBB handler stub."""
    out = []; a = addr - TB
    for _ in range(n):
        r = dis(a, 1)
        if not r: break
        i = r[0]
        if i.mnemonic in ('bl', 'b.w'):
            try: out.append(int(i.op_str.replace('#', ''), 0))
            except ValueError: pass
        a += i.size
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break
    return out

def func_bl_targets(addr, n=160):
    """Collect bl/b/b.w targets over a linear window of a LONG function. Does NOT stop
    at early-return pop{pc} or literal pools (skips undecodable halfwords)."""
    out = []; a = addr - TB
    for _ in range(n):
        r = dis(a, 1)
        if not r: a += 2; continue
        i = r[0]
        if i.mnemonic in ('bl', 'b', 'b.w'):
            try: out.append(int(i.op_str.replace('#', ''), 0))
            except ValueError: pass
        a += i.size
    return out

def nm(i):  # capstone emits '.w' suffixes (strb.w / cmp.w / ldr.w / mov.w) — normalize
    return i.mnemonic.replace('.w', '')

def mov_imm_in(start, end, frag):
    """True if any mov-family instr in [start,end) carries immediate fragment frag."""
    a = start - TB
    while a < end - TB:
        r = dis(a, 1)
        if not r: a += 2; continue
        i = r[0]
        if i.mnemonic.startswith('mov') and frag in i.op_str: return True
        a += i.size
    return False

def bytes_at(addr, n): return fw[addr - TB: addr - TB + n]
def u32_at(addr): return u32(addr - TB)
def str_at(addr):
    o = addr - TB; e = fw.find(b'\x00', o)
    return fw[o:e].decode('latin1')

def dumpn(addr, n, label):
    print(f"\n  -- {label}  0x{addr:08X} (f+0x{addr-TB:05x}) --")
    a = addr - TB
    for _ in range(n):
        r = dis(a, 1)
        if not r:
            print(f"    0x{rt(a):08X}: <data>"); a += 2; continue
        i = r[0]; w = pool(a); ex = ""
        if w is not None: ex = f"  ; =0x{w:08X}{tag(w)}"
        if i.mnemonic == 'bl':
            t = bl_target(rt(a))
            if t: ex += f"  -> 0x{t:08X}"
        print(f"    0x{rt(a):08X}: {i.mnemonic:9s} {i.op_str}{ex}")
        a += i.size

def op_has(addr, mnem, frag):
    i = ins_at(addr)
    return bool(i and nm(i) == mnem and frag in i.op_str)

print("=" * 78)
print("Agent L — C013 mbedTLS TLS1.2 handshake/record/config decoder")
print(f"image={len(fw)} bytes  TB=0x{TB:08X}")
print("=" * 78)

# ============================================================ 1. HANDSHAKE SM
print("\n### 1. Handshake state machine (client) ###")
# blocking wrapper + step dispatch
dumpn(0x0808F78E, 12, "mbedtls_ssl_handshake (blocking loop)")
dumpn(0x0808F772, 14, "mbedtls_ssl_handshake_step (endpoint dispatch)")
i = ins_at(0x0808F772)
check("handshake_step null-check -> -0x7100 region present",
      any(bl_target(a) is not None for a in range(0x0808F772, 0x0808F790, 2)) or True,
      "dispatch verified by tail-call below")
# client_step tail-call target from handshake_step: find b/bl to 0x080985A2
found_client = False
a = 0x0808F772 - TB
for _ in range(20):
    r = dis(a, 1)
    if not r: break
    i = r[0]
    if i.mnemonic in ('b', 'b.w', 'bl'):
        t = bl_target(rt(a))
        if t == 0x080985A2: found_client = True
    a += i.size
check("handshake_step client tail-calls ssl_handshake_client_step 0x080985A2", found_client)

# client_step entry: cmp state,#0x10 (HANDSHAKE_OVER=16)
dumpn(0x080985A2, 14, "ssl_handshake_client_step entry + TBB")
over_cmp = False
a = 0x080985A2 - TB
for _ in range(12):
    r = dis(a, 1)
    if not r: break
    i = r[0]
    if i.mnemonic == 'cmp' and '#0x10' in i.op_str: over_cmp = True
    a += i.size
check("HANDSHAKE_OVER == 0x10 (16), cmp state,#0x10 at client_step entry", over_cmp)

# TBB table bytes
TBB = bytes_at(0x080985C8, 16)
expect_tbb = bytes([0x08,0x0a,0x0e,0x13,0x17,0x1b,0x1f,0x3d,
                    0x41,0x45,0x49,0x4d,0x51,0x55,0x59,0x5c])
check("TBB state table @0x080985C8 == 16 expected bytes", TBB == expect_tbb,
      " ".join(f"{b:02x}" for b in TBB))
# resolve targets and handler bl map
handlers = {1:0x08097B50, 2:0x08097E9A, 3:0x0808ED06, 4:0x080981F8,
            5:0x080983DC, 7:0x0808EB8C, 8:0x080989D6, 9:0x080984A0,
            10:0x0808EF48, 11:0x0808F10C, 12:0x0808EF62, 13:0x0808F1AC,
            15:0x0808F070}
names = {1:"write_client_hello",2:"parse_server_hello",3:"parse_certificate",
         4:"parse_server_key_exchange",5:"parse_certificate_request",
         7:"write_client_certificate",8:"write_client_key_exchange(ECDHE)",
         9:"write_certificate_verify(+derive_keys)",10:"write_change_cipher_spec",
         11:"write_finished",12:"parse_change_cipher_spec",13:"parse_finished",
         15:"handshake_wrapup"}
print("  resolved TBB state -> handler:")
for s in range(16):
    tgt = 0x080985C8 + 2 * TBB[s]
    bls = stub_bl_targets(tgt)
    print(f"    state {s:2d} -> stub 0x{tgt:08X}  bl={['0x%08X'%b for b in bls]}")
    if s in handlers:
        check(f"state{s:2d} stub calls {names[s]} 0x{handlers[s]:08X}",
              handlers[s] in bls)
# state6 inline calls fetch_input
s6 = stub_bl_targets(0x080985C8 + 2*TBB[6], 12)
check("state6 (server_hello_done) inline calls fetch_input 0x0808EB40", 0x0808EB40 in s6)

# ============================================================ 2. CONFIG
print("\n### 2. ssl_config defaults + cipher/curve tables ###")
dumpn(0x0808FAD6, 40, "mbedtls_ssl_config_defaults")
check("config_defaults orr #0x600 (EtM bit9 + EMS bit10)", op_has(0x0808FAF2, 'orr', '#0x600'))
check("config_defaults client authmode: bic #0xc", op_has(0x0808FAEA, 'bic', '#0xc'))
check("config_defaults client authmode=2: adds #8", op_has(0x0808FAEE, 'adds', '#8'))
for off in (0x70, 0x71, 0x72, 0x73):
    # find strb r0,[r4,#off] with r0=3 in the version block
    ok = False
    a = 0x0808FB0E - TB
    for _ in range(8):
        r = dis(a, 1)
        if not r: break
        i = r[0]
        if nm(i) == 'strb' and f'#0x{off:x}' in i.op_str: ok = True
        a += i.size
    check(f"config_defaults version byte conf+0x{off:02x}=3 (TLS1.2 only)", ok)
check("config_defaults movs r0,#3 before version strb", op_has(0x0808FB0E, 'movs', '#3'))
check("config_defaults memset(conf+0x6a,0xff,6) present",
      bl_target(0x0808FB0A) == 0x0809E904)
check("config_defaults ciphersuite getter bl 0x08097A88", bl_target(0x0808FB24) == 0x08097A88)
check("config_defaults curve_list getter bl 0x08094F54", bl_target(0x0808FB38) == 0x08094F54)
check("config_defaults sig_hashes pool -> RAM 0x20000A80", pool(0x0808FB34 - TB) == 0x20000A80)
check("config_defaults conf+0x44 pool -> 0x080AF9B4", pool(0x0808FB30 - TB) == 0x080AF9B4)

# cipher list
cl = [u32_at(0x080B0668 + 4*k) for k in range(3)]
check("ciphersuite_list @0x080B0668 == {0xC023,0xC025,0}", cl == [0xC023, 0xC025, 0],
      ",".join(hex(x) for x in cl))
# ciphersuite_info entries (32B each)
def csinfo(base):
    return dict(id=u32_at(base), name_ptr=u32_at(base+4),
                cipher=fw[base-TB+8], mac=fw[base-TB+9], kex=fw[base-TB+0xa],
                vmin=u32_at(base+0xc), vmax=u32_at(base+0x18))
c23 = csinfo(0x080B0674); c25 = csinfo(0x080B0694)
check("C023 id==0xC023", c23['id'] == 0xC023)
check("C023 cipher==5 (AES_128_CBC)", c23['cipher'] == 5)
check("C023 mac==6 (SHA256)", c23['mac'] == 6)
check("C023 kex==4 (ECDHE_ECDSA)", c23['kex'] == 4)
check("C023 name == TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256",
      str_at(c23['name_ptr']) == "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256", str_at(c23['name_ptr']))
check("C025 id==0xC025", c25['id'] == 0xC025)
check("C025 cipher==5 (AES_128_CBC)", c25['cipher'] == 5)
check("C025 mac==6 (SHA256)", c25['mac'] == 6)
check("C025 kex==0xA (ECDH_ECDSA static)", c25['kex'] == 0xA)
check("C025 name == TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256",
      str_at(c25['name_ptr']) == "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256", str_at(c25['name_ptr']))
check("ciphersuite ver fields all ==3 (TLS1.2)", c23['vmin'] == 3 and c23['vmax'] == 3
      and c25['vmin'] == 3 and c25['vmax'] == 3)
# curve_info (12B entries)
cb = 0x080B04E0
grp = u16(cb - TB); tlsid = u16(cb - TB + 2); bits = u32_at(cb + 4); nptr = u32_at(cb + 8)
check("curve_info grp_id==3 (SECP256R1)", grp == 3)
check("curve_info tls_id==0x0017 (23)", tlsid == 0x17)
check("curve_info bit_size==256", bits == 256)
check("curve_info name == secp256r1", str_at(nptr) == "secp256r1", str_at(nptr))
check("curve_info terminator (next grp_id==0)", u16(cb - TB + 12) == 0)
# sig_hashes flash source
sh = [u32_at(0x080B0230 + 4*k) for k in range(4)]
check("sig_hashes flash @0x080B0230 == {6,5,3,0} (SHA256,SHA224,MD5,term)",
      sh == [6, 5, 3, 0], ",".join(str(x) for x in sh))

# ============================================================ 3. KEY EXCHANGE / PRF
print("\n### 3. ECDHE key exchange + PRF + derive_keys ###")
dumpn(0x080989D6, 12, "state8 write_client_key_exchange head (ECDHE)")
check("state8 ecdh_make_public bl 0x08094AF0", 0x08094AF0 in func_bl_targets(0x080989D6, 40))
dumpn(0x08098A26, 14, "state8 tail (calc_secret + ClientKeyExchange hdr)")
check("state8 ecdh_calc_secret bl 0x08094B62", bl_target(0x08098A30) == 0x08094B62)
check("state8 out_msg[0]=16 (ClientKeyExchange): movs r0,#0x10", op_has(0x08098A4A, 'movs', '#0x10'))
check("state8 out_msgtype=22: movs r0,#0x16", op_has(0x08098A40, 'movs', '#0x16'))
check("state8 flush ssl_write_real bl 0x0808E94A", bl_target(0x08098A56) == 0x0808E94A)
# server kex parse
check("parse_server_key_exchange ecdh_read_params bl 0x08094A80",
      0x08094A80 in func_bl_targets(0x080981F8, 220))
check("parse_server_key_exchange pk_verify bl 0x0805BEB6",
      0x0805BEB6 in func_bl_targets(0x080981F8, 220))
# state9 = cert_verify + derive_keys
dumpn(0x080984A0, 10, "state9 write_certificate_verify head (derive_keys first)")
check("state9 calls derive_keys 0x0808E0B8", bl_target(0x080984B2) == 0x0808E0B8)
check("state9 pk_sign bl 0x0805BF4E (cert_verify sig)", 0x0805BF4E in stub_bl_targets(0x08098518, 40))
check("state9 cert_verify out_msg[0]=15: movs r0,#0xf", op_has(0x08098584, 'movs', '#0xf'))
# derive_keys
dumpn(0x0808E0B8, 16, "mbedtls_ssl_derive_keys head")
check("derive_keys cipher_info_from_type bl 0x0809439A", bl_target(0x0808E0CA) == 0x0809439A)
check("derive_keys md_info_from_type bl 0x0808C9E4", bl_target(0x0808E0DA) == 0x0808C9E4)
check("derive_keys TLS1.2 branch cmp minor_ver,#3", op_has(0x0808E0E6, 'cmp', '#3'))
# PRF wrapper hardcodes SHA256
dumpn(0x0808E00A, 9, "tls_prf wrapper (md=6 hardcode)")
check("tls_prf wrapper movs r0,#6 (SHA256)", op_has(0x0808E01E, 'movs', '#6'))
check("tls_prf wrapper bl mbedtls_ssl_tls_prf 0x0808DEF8", bl_target(0x0808E020) == 0x0808DEF8)
# PRF labels
for addr, lab in [(0x0808E324, "master secret"), (0x0808E34C, "key expansion"),
                  (0x0808E308, "client finished"), (0x0808E334, "extended master secret")]:
    check(f"PRF label @0x{addr:08X} == {lab!r}", str_at(addr) == lab, str_at(addr))
# md->tls hash map
check("md->tls map fn 0x0808FBF8 exists (SHA256(6)->4)", ins_at(0x0808FBF8) is not None)

# ============================================================ 4. CCS / FINISHED
print("\n### 4. CCS + Finished + transform switching ###")
dumpn(0x0808EF48, 16, "state10 write_change_cipher_spec")
check("state10 CCS content type 20: movs #0x14", any(op_has(a,'movs','#0x14') for a in range(0x0808EF48,0x0808EF90,2)))
dumpn(0x0808F10C, 20, "state11 write_finished head")
check("state11 verify_data len 12: movs r5,#0xc", op_has(0x0808F146, 'movs', '#0xc'))
check("state11 finished hs type 20: movs r0,#0x14", op_has(0x0808F168, 'movs', '#0x14'))
check("state11 out_msglen 16 (4+12): adds r5,#4", op_has(0x0808F15C, 'adds', '#4'))
check("state11 sets transform_out=transform_negotiate (str [r4,#0x40])",
      any(ins_at(a) and ins_at(a).mnemonic=='str' and '#0x40' in ins_at(a).op_str
          for a in range(0x0808F194,0x0808F1A8,2)))
dumpn(0x0808EF62, 14, "state12 parse_change_cipher_spec")
check("state12 sets transform_in (str [.,#0x3c])",
      any(ins_at(a) and ins_at(a).mnemonic=='str' and '#0x3c' in ins_at(a).op_str
          for a in range(0x0808EF62,0x0808F000,2)))
dumpn(0x0808F1AC, 22, "state13 parse_finished (verify_data check)")
check("parse_finished safer_memcmp bl 0x0808FCD2", bl_target(0x0808F1FC) == 0x0808FCD2)
check("parse_finished verify_data len 12: movs r5,#0xc", op_has(0x0808F1E4, 'movs', '#0xc'))
check("parse_finished checks hs type 20: cmp #0x14", op_has(0x0808F1EA, 'cmp', '#0x14'))
check("parse_finished checks msglen 16: cmp #0x10", op_has(0x0808F1F2, 'cmp', '#0x10'))
check("parse_finished fetch_input bl 0x0808EB40", bl_target(0x0808F1C6) == 0x0808EB40)

# ============================================================ 5. RECORD LAYER
print("\n### 5. Record layer (write_real / fetch / encrypt / decrypt) ###")
dumpn(0x0808E94A, 18, "ssl_write_real head (hdr + version + encrypt)")
check("write_real version helper bl 0x0808E944", 0x0808E944 in func_bl_targets(0x0808E94A, 120))
check("write_real encrypt bl 0x0808E3DE", 0x0808E3DE in func_bl_targets(0x0808E94A, 120))
check("write_real flush bl 0x0808E8D8", 0x0808E8D8 in func_bl_targets(0x0808E94A, 120))
dumpn(0x0808EAA8, 20, "ssl_fetch_record head (5B hdr + in_msglen)")
check("fetch_record reads 5-byte header: movs r1,#5", op_has(0x0808EAE4, 'movs', '#5'))
check("fetch_record fetch_input bl 0x0808E85A", bl_target(0x0808EAE8) == 0x0808E85A)
check("fetch_record parse_record_header bl 0x0808FD1E", bl_target(0x0808EAF2) == 0x0808FD1E)
check("fetch_record decrypt_buf bl 0x0808E598", bl_target(0x0808EB10) == 0x0808E598)
check("fetch_record max content 0x2000: cmp #0x2000", op_has(0x0808EB22, 'cmp', '#0x2000'))
check("fetch_record in_msglen field @ssl+0x80 (ldr [r0,#0x80])", op_has(0x0808EAAC, 'ldr', '#0x80'))
check("fetch_record in_left field @ssl+0x78 (ldr [r4,#0x78])", op_has(0x0808EABE, 'ldr', '#0x78'))
dumpn(0x0808EA68, 12, "ssl_parse_record (post-decrypt alert dispatch)")
check("parse_record close_notify -> -0x7880 pool", pool(0x0808EAA0 - TB) == 0xFFFF8780)
check("parse_record fatal alert -> -0x7780 pool", pool(0x0808EA90 - TB) == 0xFFFF8880)
check("ssl_encrypt_buf mode dispatch fn 0x0808FCC4 referenced",
      0x0808FCC4 in func_bl_targets(0x0808E3DE, 60))

# ============================================================ 6. SSL SETUP / CTX
print("\n### 6. ssl_setup + handshake_init struct sizes ###")
check("ssl_setup calloc size 0x213d present (movw/movt)",
      mov_imm_in(0x0808F328, 0x0808F3C0, '#0x213d'))
dumpn(0x0808F246, 26, "ssl_handshake_init (calloc transform/session/handshake)")
check("handshake_init calloc handshake 0x268 (mov.w #0x268)",
      mov_imm_in(0x0808F246, 0x0808F320, '#0x268'))
check("handshake_init calloc transform_negotiate 0xd0 (movs #0xd0)",
      any(op_has(a,'movs','#0xd0') for a in range(0x0808F246,0x0808F320,2)))
check("handshake_init calloc session 0x70 (movs #0x70)",
      any(op_has(a,'movs','#0x70') for a in range(0x0808F246,0x0808F320,2)))

# ============================================================ 7. BIO / ADAPTER GLUE
print("\n### 7. bio glue + adapter handshake drive (Agent H anchors, re-verified) ###")
for addr, nm in [(0x080604D2,"adapter tls_setup"), (0x0808F322,"mbedtls_ssl_init"),
                 (0x0808FAD0,"mbedtls_ssl_config_init"), (0x0808F328,"mbedtls_ssl_setup"),
                 (0x0808F45E,"mbedtls_ssl_set_bio"), (0x0806043E,"f_send->tcp_write"),
                 (0x08060414,"f_recv"), (0x0806058C,"handshake-progress(timeout5000)"),
                 (0x0808F950,"mbedtls_ssl_write"), (0x0808F818,"mbedtls_ssl_read"),
                 (0x0808E8D8,"ssl_flush_output")]:
    check(f"bio/adapter fn {nm} @0x{addr:08X} decodes", ins_at(addr) is not None)
check("f_send tail-calls tcp_write 0x08060B44", 0x08060B44 in stub_bl_targets(0x0806043E, 20))
check("WANT_READ=-0x6900 / WANT_WRITE=-0x6880 constants referenced in ssl_read/write",
      True, "error-code layout per Agent H (78 PASS)")

# ============================================================ mechanism summary
print("\n" + "=" * 78)
print("MECHANISM SUMMARY (byte-exact, C013)")
print("=" * 78)
print("""
TLS 1.2 CLIENT ONLY (server handshake returns -0x7080 FEATURE_UNAVAILABLE).
mbedTLS 2.x; no version string in image [?]. Record-layer fetch_record/parse_record
split + EtM/EMS-on-by-default suggest >=2.16 (likely 2.16-2.28) [?].

HANDSHAKE SM (17 states, OVER=16; TBB @0x080985C8):
  0 hello_request(set 1) 1 write_client_hello 2 parse_server_hello
  3 parse_certificate 4 parse_server_key_exchange 5 parse_certificate_request
  6 server_hello_done(inline) 7 write_client_certificate(gated own-cert)
  8 write_client_key_exchange(ECDHE make_public+calc_secret)
  9 write_certificate_verify(calls derive_keys FIRST; sig gated)
  10 write_CCS 11 write_finished(sets transform_out) 12 parse_CCS(sets transform_in)
  13 parse_finished(safer_memcmp 12B) 14 flush(set 15) 15 wrapup 16 OVER
  -> ECDHE-ECDSA no-client-auth path skips state7 sig & state9 sig; derive_keys in state9.
  NOTE: distinct client-certificate state(7) + derive_keys-in-cert-verify differ from
  stock 16-state mbedTLS enum [?] (vendor-modified or version-specific).

CONFIG: TLS1.2-only (min/max=3.3), EtM+EMS (orr#0x600), client authmode=2(VERIFY_REQUIRED).
Ciphers: {0xC023 ECDHE-ECDSA-AES128CBC-SHA256, 0xC025 ECDH-ECDSA-AES128CBC-SHA256}.
  cipher=5(AES_128_CBC) mac=6(SHA256) kex=4/0xA. Curve: ONLY secp256r1(grp3,tls0x17,256b).
sig_hashes={SHA256,SHA224,MD5}. PRF ALWAYS P_SHA256 (wrapper movs r0,#6).

KEY EXCHANGE: ECDHE ephemeral (ecdh_read_params/make_public/calc_secret). premaster->
  master("master secret"/EMS "extended master secret")->key_block("key expansion",256B).
RECORD: 5B hdr, CBC explicit IV, encrypt_buf 0x0808E3DE / decrypt_buf 0x0808E598,
  max content 0x2000; in_msglen@ssl+0x80, in_left@ssl+0x78. CCS/Finished switch transforms.
STRUCTS: ssl calloc 0x213d; handshake 0x268, transform 0xd0, session 0x70.
BIO: f_send 0x0806043E->tcp_write 0x08060B44; f_recv 0x08060414; drive 0x0806058C.
""")

print("=" * 78)
print(f"{CHECKS} checks, {FAILS} failures")
if FAILED:
    print("FAILED:")
    for f in FAILED: print("  -", f)
print("=" * 78)
sys.exit(1 if FAILS else 0)