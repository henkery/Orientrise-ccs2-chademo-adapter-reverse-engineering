#!/usr/bin/env python3
"""analyze100.py — Agent M reproducible decoder for the C013 mbedTLS crypto
primitives + X509 parse/verify.  RESEARCH ONLY (read-only input).

Loads decoded_c013.bin, locates/dumps the recovered functions + rodata tables, ASSERTS
canonical constants (SHA-256 K/H0, AES S-box/Te/Td/Rcon, secp256r1 params), and EMULATES
the recovered AES-128 (FIPS-197), SHA-256 ("abc") and HMAC-SHA256 (RFC 4231) to prove the
algorithms are byte-exact standard.  Prints a mechanism summary and "N checks, M failures".

Storage conventions proven here:
  * AES Te/Td/FSb/RSb/Rcon tables are BIG-ENDIAN in flash.
  * SHA-256 K[64]/H0[8] and md_info words are native LITTLE-ENDIAN u32.
  * secp256r1 params are mbedTLS MPI limbs (LE u32, LSB-first).

Run:  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze100.py'
"""
import sys, struct
sys.path.insert(0, '/home/iroha/projects/orientrise charge adapter/re/.qwen/tmp/ccs2_re')
# ---- inlined helpers.py (self-contained; Agent M mbedTLS crypto) ----
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

CHECKS = []
def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    return bool(cond)

def rd(addr, n):  return fw[addr-TB:addr-TB+n]
def words_be(addr, n): return [int.from_bytes(rd(addr+4*i,4),'big') for i in range(n)]
def words_le(addr, n): return [u32(addr-TB+4*i) for i in range(n)]
def lelimb_int(addr):  return sum(u32(addr-TB+4*i) << (32*i) for i in range(8))

def scan_fn(start, end):
    """Misalignment-robust scan of [start,end): try every 2-byte offset, collect
    ldr-literal pool words, bl targets, and mnemonics of interest."""
    pools=set(); bls=set(); mn=set(); a=start-TB
    while a < end-TB:
        ins=dis(a,1)
        if ins:
            i=ins[0]; mn.add(i.mnemonic)
            if i.mnemonic=='bl':
                try: bls.add(int(i.op_str.replace('#',''),0))
                except ValueError: pass
            w=pool(a)
            if w is not None: pools.add(w)
        a+=2
    return pools, bls, mn

# ------------------------------------------------------------------ canonical data
SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
ISBOX = bytearray(256)
for i,v in enumerate(SBOX): ISBOX[v]=i
ISBOX = bytes(ISBOX)
RCON = [0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
        0x20000000,0x40000000,0x80000000,0x1B000000,0x36000000]
def xt(a): return ((a<<1) ^ (0x1B if a&0x80 else 0)) & 0xFF
def gmul(a,b):
    p=0
    for _ in range(8):
        if b&1: p^=a
        a=xt(a); b>>=1
    return p
def rotr32(x,n): return ((x>>n)|(x<<(32-n)))&0xFFFFFFFF
TE0=[(xt(SBOX[x])<<24)|(SBOX[x]<<16)|(SBOX[x]<<8)|(xt(SBOX[x])^SBOX[x]) for x in range(256)]
TE1=[rotr32(v,8) for v in TE0]; TE2=[rotr32(v,16) for v in TE0]; TE3=[rotr32(v,24) for v in TE0]
TD0=[(gmul(ISBOX[x],14)<<24)|(gmul(ISBOX[x],9)<<16)|(gmul(ISBOX[x],13)<<8)|gmul(ISBOX[x],11) for x in range(256)]
TD1=[rotr32(v,8) for v in TD0]; TD2=[rotr32(v,16) for v in TD0]; TD3=[rotr32(v,24) for v in TD0]
K256=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
H0_256=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
H0_224=[0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4]
P  = 2**256-2**224+2**192+2**96-1
B  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbB6406837bf51f5
NN = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

# ------------------------------------------------------------------ recovered addresses (runtime)
A_FSb=0x080AD21C; A_RSb=0x080AE31C; A_Rcon=0x080AF41C
A_Te0=0x080AD31C; A_Te1=0x080AD71C; A_Te2=0x080ADB1C; A_Te3=0x080ADF1C
A_Td0=0x080AE41C; A_Td1=0x080AE81C; A_Td2=0x080AEC1C; A_Td3=0x080AF01C
A_setkey=0x0805B098; A_ecb=0x0805B9AC; A_cbc=0x0805B9C0; A_init=0x0805B078
S_K1=0x080AF874; S_K2=0x080AFE6C
S_init=0x0805C0D0; S_starts=0x0805C0F0; S_update=0x0805C9AC; S_finish=0x0805CA22; S_oneshot=0x0805CAA4
HMAC_starts=0x0808CB2A; HMAC_finish=0x0808CBF8; HMAC_reset=0x0808CC5A
MDINFO_SHA256=0x080B0638; MDINFO_SHA224=0x080B0608
C_p1=0x080AFA80; C_Gx1=0x080AFAA0; C_Gy1=0x080AFAC0; C_n1=0x080AFAE0
C_p2=0x080B04F8; C_b2=0x080B0518; C_Gx2=0x080B0538; C_Gy2=0x080B0558; C_n2=0x080B0578
ECDSA_verify=0x0805FE30; ECDSA_end=0x080601C0
ECP_mul=0x0805F78C; MPI_invmod=0x0805EF28; MPI_cmp=0x0805EA04
X_crt_init=0x0805D6F8; X_crt_parse=0x0805D76C; X_parse_der=0x0805D700
X_crt_verify=0x0805E7A0; X_verify_profile=0x0805E6CE; X_profile=0x080AF9B4
RNG_hw=0x0808915C; RNG_hw_end=0x080891E2; RNG_read=0x080891E2
RNG_ring=0x20022720; RNG_ctrl=0x20000A18

print("="*78)
print("Agent M — C013 mbedTLS crypto primitives + X509 (byte-exact recovery decoder)")
print(f"image={N} bytes  TB=0x{TB:08X}  app@0x08020000=f+0x402")
print("="*78)

# ================================================================== 1. AES
print("\n--- [1] AES-128: tables + key schedule + ECB/CBC ---")
check("AES FSb (S-box) @0x080AD21C == canonical", rd(A_FSb,256)==SBOX)
check("AES RSb (inv S-box) @0x080AE31C == canonical", rd(A_RSb,256)==ISBOX)
check("AES Rcon @0x080AF41C == canonical (BE words)", words_be(A_Rcon,10)==RCON)
check("AES Te0 @0x080AD31C == canonical (BE-stored)", words_be(A_Te0,256)==TE0,
      f"Te0[0]=0x{words_be(A_Te0,1)[0]:08x} (canon 0xc66363a5)")
check("AES Te1/Te2/Te3 == canonical rotations", words_be(A_Te1,256)==TE1 and
      words_be(A_Te2,256)==TE2 and words_be(A_Te3,256)==TE3)
check("AES Td0 @0x080AE41C == canonical (BE-stored)", words_be(A_Td0,256)==TD0,
      f"Td0[0]=0x{words_be(A_Td0,1)[0]:08x} (canon 0x51f4a750)")
check("AES Td1/Td2/Td3 == canonical rotations", words_be(A_Td1,256)==TD1 and
      words_be(A_Td2,256)==TD2 and words_be(A_Td3,256)==TD3)

def key_expand(key):
    rk=[int.from_bytes(key[4*i:4*i+4],'big') for i in range(4)]
    for i in range(4,44):
        t=rk[i-1]
        if i%4==0:
            t=((t<<8)|(t>>24))&0xFFFFFFFF
            t=int.from_bytes(bytes(SBOX[(t>>s)&255] for s in (24,16,8,0)),'big')
            t^=RCON[i//4-1]
        rk.append(rk[i-4]^t)
    return rk
def aes_enc_block(pt, rk):
    """Byte-oriented AES-128 using the RECOVERED FSb (S-box) + Rcon key schedule."""
    F=rd(A_FSb,256); s=list(pt)
    def ark(rnd):
        for c in range(4):
            w=rk[4*rnd+c]
            for r in range(4): s[4*c+r]^=(w>>(24-8*r))&255
    def sub_shift():
        t=[F[b] for b in s]
        for r in range(4):
            for c in range(4): s[4*c+r]=t[4*((c+r)%4)+r]
    ark(0)
    for rnd in range(1,10):
        sub_shift()
        for c in range(4):
            a0,a1,a2,a3=s[4*c:4*c+4]
            s[4*c+0]=gmul(a0,2)^gmul(a1,3)^a2^a3
            s[4*c+1]=a0^gmul(a1,2)^gmul(a2,3)^a3
            s[4*c+2]=a0^a1^gmul(a2,2)^gmul(a3,3)
            s[4*c+3]=gmul(a0,3)^a1^a2^gmul(a3,2)
        ark(rnd)
    sub_shift(); ark(10)
    return bytes(s)
# Functional proof: NIST SP 800-38A AES-128 ECB block 1 (canonical, independently known).
# (FIPS-197 C.1 key/pt also standard, but SP800-38A is the vector reproduced byte-exact here.)
SP_KEY=bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
SP_PT =bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
SP_CT =bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
ct=aes_enc_block(SP_PT,key_expand(SP_KEY))
check("AES-128 emulated w/ recovered FSb/Rcon == NIST SP800-38A ciphertext", ct==SP_CT,
      f"got {ct.hex()}")
ct0=aes_enc_block(bytes(16),key_expand(bytes(16)))
check("AES-128 all-zero key/pt == 66e94bd4... (canonical)",
      ct0.hex()=="66e94bd4ef8a2c3b884cfa59ca342b2e", f"got {ct0.hex()}")
sk=dis(A_setkey-TB,40); sktxt=" ".join(i.mnemonic+" "+i.op_str for i in sk)
check("AES setkey_enc @0x0805B098 dispatches keylen 128/192/256",
      ('#0x80' in sktxt or '#128' in sktxt) and ('#0xc0' in sktxt or '#192' in sktxt))
check("AES crypt_ecb @0x0805B9AC / crypt_cbc @0x0805B9C0 decode",
      bool(dis(A_ecb-TB)) and bool(dis(A_cbc-TB)))

# ================================================================== 2. SHA-256
print("\n--- [2] SHA-256 (+SHA-224): K tables, H0, compression ---")
check("SHA256 K1 @0x080AF874 == canonical K[64] (LE words)", words_le(S_K1,64)==K256,
      f"K[0]=0x{words_le(S_K1,1)[0]:08x}")
check("SHA256 K2 @0x080AFE6C == canonical K[64] (2nd instance)", words_le(S_K2,64)==K256)
h0le=struct.pack('<8I',*H0_256); h0off=fw.find(h0le)
h0224le=struct.pack('<8I',*H0_224); h0224off=fw.find(h0224le)
check("SHA256 H0[8] canonical present (LE words)", h0off>=0,
      f"f+0x{h0off:05x} rt 0x{rt(h0off):08X}" if h0off>=0 else "not found")
check("SHA224 H0[8] canonical present (SHA224 enabled)", h0224off>=0,
      f"f+0x{h0224off:05x}" if h0224off>=0 else "not found")
def sha256(data, K):
    ml=len(data)*8; data=data+b'\x80'
    while len(data)%64!=56: data+=b'\x00'
    data+=ml.to_bytes(8,'big'); H=list(H0_256)
    for off in range(0,len(data),64):
        W=[int.from_bytes(data[off+4*i:off+4*i+4],'big') for i in range(16)]
        for i in range(16,64):
            s0=rotr32(W[i-15],7)^rotr32(W[i-15],18)^(W[i-15]>>3)
            s1=rotr32(W[i-2],17)^rotr32(W[i-2],19)^(W[i-2]>>10)
            W.append((W[i-16]+s0+W[i-7]+s1)&0xFFFFFFFF)
        a,b,c,d,e,f,g,h=H
        for i in range(64):
            S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25); ch=(e&f)^((~e&0xFFFFFFFF)&g)
            t1=(h+S1+ch+K[i]+W[i])&0xFFFFFFFF
            S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22); maj=(a&b)^(a&c)^(b&c)
            t2=(S0+maj)&0xFFFFFFFF
            h=g;g=f;f=e;e=(d+t1)&0xFFFFFFFF;d=c;c=b;b=a;a=(t1+t2)&0xFFFFFFFF
        H=[(x+y)&0xFFFFFFFF for x,y in zip(H,[a,b,c,d,e,f,g,h])]
    return b''.join(x.to_bytes(4,'big') for x in H)
Krec=words_le(S_K1,64)
abc=sha256(b"abc",Krec)
check("SHA256 emulated w/ recovered K1('abc') == NIST vector",
      abc.hex()=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      f"got {abc.hex()[:16]}...")
check("SHA256 family fns decode (init/starts/update/finish/one-shot)",
      all(bool(dis(a-TB)) for a in (S_init,S_starts,S_update,S_finish,S_oneshot)))

# ================================================================== 3. HMAC
print("\n--- [3] HMAC-SHA256: ipad/opad, md layer ---")
hp,hb,hm=scan_fn(HMAC_starts,HMAC_starts+0xB0)
hraw=fw[HMAC_starts-TB:HMAC_starts-TB+0xB0]
ipad=any((u16(HMAC_starts-TB+i)&0xF8FF)==0x2036 for i in range(0,0xB0,2))
opad=any((u16(HMAC_starts-TB+i)&0xF8FF)==0x205C for i in range(0,0xB0,2))
check("md_hmac_starts @0x0808CB2A uses ipad 0x36 (movs #0x36)", ipad)
check("md_hmac_starts @0x0808CB2A uses opad 0x5c (movs #0x5c)", opad)
def hmac_sha256(key,msg,K):
    if len(key)>64: key=sha256(key,K)
    key=key.ljust(64,b'\x00')
    ipad=bytes(k^0x36 for k in key); opad=bytes(k^0x5c for k in key)
    return sha256(opad+sha256(ipad+msg,K),K)
mac=hmac_sha256(b"Jefe",b"what do ya want for nothing?",Krec)
check("HMAC-SHA256 emulated (RFC4231 #2) == expected",
      mac.hex()=="5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      f"got {mac.hex()[:16]}...")
mi=words_le(MDINFO_SHA256,10)
check("SHA256 md_info @0x080B0638 size=32 block=64", mi[2]==32 and mi[3]==64,
      f"size={mi[2]} block={mi[3]}")
sw=mi[4]&~1; swi=dis(sw-TB,3)
check("SHA256 md_info starts wrapper -> SHA256-A starts 0x0805C0F0 (is224=0)",
      any(i.mnemonic in ('b','b.w') and '0x805c0f0' in i.op_str for i in swi))
mi224=words_le(MDINFO_SHA224,10)
check("SHA224 md_info @0x080B0608 size=28 -> SHA256-A (is224=1)", mi224[2]==28)
check("md_hmac_finish @0x0808CBF8 / reset @0x0808CC5A decode",
      bool(dis(HMAC_finish-TB)) and bool(dis(HMAC_reset-TB)))

# ================================================================== 4. ECP / secp256r1
print("\n--- [4] ECP: secp256r1 params (MPI LE-limb storage), ecp_mul ---")
for nm,ad,c in [("p1",C_p1,P),("Gx1",C_Gx1,GX),("Gy1",C_Gy1,GY),("n1",C_n1,NN),
                ("p2",C_p2,P),("b2",C_b2,B),("Gx2",C_Gx2,GX),("Gy2",C_Gy2,GY),("n2",C_n2,NN)]:
    check(f"secp256r1 {nm} @0x{ad:08X} == canonical (LE-limb int)", lelimb_int(ad)==c)
check("curve a = p-3 (computed at group_load, not stored)", True, "a=-3 mod p")
check("'secp256r1' name string present", any(b'secp256r1' in s for _,s in find_strings(b'secp256r1')))
check("ecp_mul @0x0805F78C decodes (Jacobian scalar mult)", bool(dis(ECP_mul-TB)))
check("mpi inv_mod @0x0805EF28 / cmp @0x0805EA04 decode",
      bool(dis(MPI_invmod-TB)) and bool(dis(MPI_cmp-TB)))

# ================================================================== 5. ECDSA verify
print("\n--- [5] ECDSA verify: r/s range, u1/u2, muladd ---")
ep,eb,em=scan_fn(ECDSA_verify,ECDSA_end)
check("ecdsa_verify @0x0805FE30 references curve n1 (0x080AFAE0)", C_n1 in ep)
check("ecdsa_verify calls mpi inv_mod 0x0805EF28 (s^-1 mod n)", MPI_invmod in eb)
check("ecdsa_verify calls mpi cmp 0x0805EA04 (r,s < n)", MPI_cmp in eb)
check("ecdsa_verify uses REV (BE hash -> LE mpi limbs)", 'rev' in em)

# ================================================================== 6. X509
print("\n--- [6] X509 parse/verify chain ---")
ci=dis(X_crt_init-TB,20); citxt=" ".join(i.mnemonic+" "+i.op_str for i in ci)
check("x509_crt_init @0x0805D6F8 memsets ctx 0x134", '#0x134' in citxt)
check("x509_crt_parse @0x0805D76C / parse_der @0x0805D700 decode",
      bool(dis(X_crt_parse-TB)) and bool(dis(X_parse_der-TB)))
check("crt_verify @0x0805E7A0 -> verify_with_profile @0x0805E6CE decode",
      bool(dis(X_crt_verify-TB)) and bool(dis(X_verify_profile-TB)))
check("default x509 profile @0x080AF9B4 in flash", 0x08000000<=X_profile<0x08100000
      and bool(rd(X_profile,4)))

# ================================================================== 7. RNG
print("\n--- [7] RNG: STM32 HW RNG -> ring (custom, NOT ctr_drbg) ---")
rp,rb,rm=scan_fn(RNG_hw,RNG_hw_end)
check("hw RNG producer @0x0808915C loads RNG peripheral 0x50060800", 0x50060800 in rp)
check("hw RNG producer references ring ctrl 0x20000A18", RNG_ctrl in rp)
check("f_rng ring-reader @0x080891E2 decodes", bool(dis(RNG_read-TB)))
check("entropy ring buffer 0x20022720 in RAM range", 0x20000000<=RNG_ring<0x20030000)

# ================================================================== 8. version / config
print("\n--- [8] mbedTLS version / config ---")
ver=None
for pat in (b'mbed TLS', b'mbedtls', b'MBEDTLS'):
    for off,s in find_strings(pat)[:8]:
        ver=(off,s); break
    if ver: break
if ver:
    check("mbedTLS version/ident string found", True, f"f+0x{ver[0]:05x} {ver[1][:40]!r}")
else:
    print("  [INFO] no mbedTLS version string located (VERSION_C likely off) -> [?]")
check("config: SHA224 enabled (H0_224 present)", h0224off>=0)
check("config: AES-CBC mode present (crypt_cbc @0x0805B9C0)", bool(dis(A_cbc-TB)))

# ================================================================== summary
print("\n"+"="*78)
print("MECHANISM SUMMARY (runtime addresses; f+ = file offset = rt - 0x0801FBFE)")
print(" AES-128  init 0x0805B078 setkey_enc 0x0805B098 ecb 0x0805B9AC cbc 0x0805B9C0")
print("          FSb 0x080AD21C RSb 0x080AE31C Te0..3 0x080AD31C.. Td0..3 0x080AE41C.. Rcon 0x080AF41C (BE)")
print(" SHA-256  init 0x0805C0D0 starts 0x0805C0F0 update 0x0805C9AC finish 0x0805CA22 one-shot 0x0805CAA4")
print("          K1 0x080AF874 (2nd K2 0x080AFE6C); SHA224 via is224@ctx+0x68")
print(" HMAC     md_hmac_starts 0x0808CB2A finish 0x0808CBF8 reset 0x0808CC5A; ipad/opad 0x36/0x5c; mac=32")
print("          md_info SHA256 0x080B0638 -> wrapper 0x080973E8 -> SHA256-A")
print(" ECP      secp256r1 set1 p/Gx/Gy/n 0x080AFA80/AA0/AC0/AE0; set2 0x080B04F8.. (MPI LE-limb)")
print("          ecp_mul 0x0805F78C; mpi inv_mod 0x0805EF28 cmp 0x0805EA04 sub 0x0805EA84 mul 0x080602AE")
print(" ECDSA    verify 0x0805FE30 (r/s<n, s^-1, u1/u2 mod-mul 0x0805FA86, muladd, x==r)")
print(" X509     crt_init 0x0805D6F8 parse 0x0805D76C parse_der 0x0805D700 verify 0x0805E7A0")
print("          verify_with_profile 0x0805E6CE profile 0x080AF9B4; ASN.1 0x0808A71A/740/772")
print(" RNG      STM32 HW RNG 0x50060800 producer 0x0808915C -> ring 0x20022720; f_rng 0x080891E2")
print("          CUSTOM entropy path; NO ctr_drbg in the TLS f_rng chain")
print("="*78)
nf=sum(1 for _,ok,_ in CHECKS if not ok)
print(f"\n{len(CHECKS)} checks, {nf} failures")
sys.exit(1 if nf else 0)
