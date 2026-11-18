#!/usr/bin/env python3
"""make_service_upg.py — build a service UPG from a stock UPG (+ optional patches).

Implements the cracked UPG format / integrity mechanics (REPORT §4.1, §5.12):
  raw[0:2]  self-describing XOR key: key0=raw[0], key1=raw[0]^raw[1]
  decoded   00 key0 | $$header[2:58] | prefix-ciphertext[58:3EA] | footer[3EA:400]
            | entry-header[400:40A] | app-code[40A:n-4] | trailer[n-4:n]
  footer    u16LE @0x3FE = CRC16/MODBUS(dec[0x3EA:0x3FE])
  trailer   u16LE @n-2   = CRC16/MODBUS(dec[2:n-2]);  dec[n-4:n-2] == 00 00 (key echo)
  length    u32LE @0x3F2 = filesize - 0x404  (app-code byte count)
  first4    u32   @0x400 = per-image IV/nonce — KEPT STOCK (no CRC relation)
  entry     file[0x000:0x45E] reused verbatim (bootloader patches MSP/PSP at install)

The prefix ciphertext [58:3EA] is kept verbatim, so its per-image keystream is NOT
needed; both CRCs are recomputed over the (possibly patched) decoded bytes.

Default (no patches) re-emits a byte-identical UPG — a round-trip proof of the format.
--dump-hook appends an EXPERIMENTAL bootloader-dump cave (see build_dump_hook) and is
gated on bench verification: the app literal pools are +2-byte packed (REPORT §5.13),
so runtime addresses / free RAM / FatFs re-entrancy must be confirmed on a bench dump
before flashing. Recovery to stock is preserved because the stock update path is left
intact (the hook only adds a one-shot dump before the normal flash write).

Usage:
  python3 make_service_upg.py STOCK.UPG -o SERVICE.UPG
  python3 make_service_upg.py STOCK.UPG -o SERVICE.UPG --patch 0x910ac:B570...
  python3 make_service_upg.py STOCK.UPG -o SERVICE_DUMP.UPG --dump-hook
"""
import sys, struct, argparse

# ---- CRC16/MODBUS (poly 0x8005 reflected 0xA001, init 0xFFFF, refin/refout, xorout 0)
TAB = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xA001 if _c & 1 else _c >> 1
    TAB.append(_c)

def modbus(d):
    c = 0xFFFF
    for b in d:
        c = (c >> 8) ^ TAB[(c ^ b) & 0xFF]
    return c

def derive_key(raw):
    return bytes([raw[0], raw[0] ^ raw[1]])

def xor_crypt(data, key):
    return bytes(b ^ key[i & 1] for i, b in enumerate(data))

LEN_OFF, FOOT_CRC_OFF, FIRST4_OFF = 0x3F2, 0x3FE, 0x400
FOOT_LO, FOOT_HI = 0x3EA, 0x3FE
ENTRY_SHELL_END, APP_START = 0x45E, 0x40A

def check_integrity(dec, label):
    n = len(dec)
    foot = struct.unpack_from('<H', dec, FOOT_CRC_OFF)[0]
    tr = struct.unpack_from('<H', dec, n - 2)[0]
    cf, ct = modbus(dec[FOOT_LO:FOOT_HI]), modbus(dec[2:n - 2])
    okf, okt = cf == foot, ct == tr
    print(f"  [{label}] footer stored=0x{foot:04X} calc=0x{cf:04X} {'OK' if okf else 'MISMATCH'}; "
          f"trailer stored=0x{tr:04X} calc=0x{ct:04X} {'OK' if okt else 'MISMATCH'}")
    return okf and okt

def build(raw, patches=(), append=None, verbose=True):
    """patches: iterable of (file_offset, bytes). append: (cave_file_offset, cave_bytes)
    placed in unused flash, extending the image. Returns new raw UPG bytes."""
    key = derive_key(raw)
    dec = bytearray(xor_crypt(raw, key))
    n = len(dec)
    if verbose:
        print(f"  key={key.hex()} decoded={n} (0x{n:x}) bytes")
        check_integrity(dec, 'stock')
    body = bytearray(dec[:n - 4])           # drop 4-byte trailer
    for off, data in patches:
        if off < APP_START:
            raise ValueError(f"patch @0x{off:x} touches protected entry-shell/prefix (<0x{APP_START:x})")
        if off + len(data) > len(body):
            raise ValueError(f"patch @0x{off:x} beyond app end 0x{len(body):x} (use append for caves)")
        body[off:off + len(data)] = data
    if append is not None:
        cave_off, cave = append
        if cave_off < len(body):
            raise ValueError("append cave overlaps existing app code")
        if cave_off + len(cave) > 0xA0000 - 4:
            raise ValueError("cave exceeds app flash region (sector 9 end 0x080C0000)")
        body.extend(b'\xFF' * (cave_off - len(body)))   # erased-flash padding
        body.extend(cave)
    new = body + b'\x00\x00\x00\x00'        # trailer: 00 00 key-echo + CRC placeholder
    nn = len(new)
    struct.pack_into('<I', new, LEN_OFF, nn - 0x404)
    struct.pack_into('<H', new, FOOT_CRC_OFF, modbus(new[FOOT_LO:FOOT_HI]))
    struct.pack_into('<H', new, nn - 2, modbus(new[2:nn - 2]))
    out = xor_crypt(bytes(new), key)
    if verbose:
        print(f"  rebuilt={nn} (0x{nn:x}) bytes; length field=0x{nn-0x404:x}")
        rt = bytearray(xor_crypt(out, key))
        check_integrity(rt, 'rebuilt')
        # verbatim: key/header/prefix [0:3EA] and entry-header+startup [400:45E];
        # the footer metadata [3EA:400] (length@3F2, CRC@3FE) legitimately changes.
        assert bytes(rt[:FOOT_LO]) == bytes(dec[:FOOT_LO]), "key/header/prefix changed!"
        assert bytes(rt[FIRST4_OFF:ENTRY_SHELL_END]) == bytes(dec[FIRST4_OFF:ENTRY_SHELL_END]), "entry header/startup changed!"
        assert struct.unpack_from('<I', rt, FIRST4_OFF)[0] == struct.unpack_from('<I', dec, FIRST4_OFF)[0], "first4 changed!"
        print("  verbatim [0:3EA] + entry[400:45E] + first4@400 preserved: OK")
    return out

# ---------------------------------------------------------------------------
# EXPERIMENTAL bootloader-dump cave (hand-encoded Thumb, capstone-verified).
# Hook: flash-writer entry file 0x910AC (runtime 0x080B10AC) -> b.w cave.
# Cave: one-shot dump of boot flash 0x08000000..0x08020000 to "0:/BOOT.BIN" via
#       FatFs f_open/f_write/f_close, guarded by a RAM magic flag, then re-executes
#       the original flash-writer prologue and continues (stock write preserved).
# ASSUMPTIONS (bench-verify before flashing — REPORT §5.13):
#   * FatFs API runs in place at BASE+file_offset (entry contract §5.12 supports this);
#     f_open=0x0363E0, f_write=0x0366C8, f_sync=0x03685A, f_close=0x0368E8 confirmed
#     (analyze67: f_close calls f_sync then clears fp->obj.fs; f_sync flushes the dir
#     entry size, so BOOT.BIN is finalized at 0x20000 B, not 0).
#   * free RAM at 0x2003F000 (FIL 0x228 B), BW 0x2003F230, FLAG 0x2003F234 — app RAM
#     map not statically known; confirm no overlap.
#   * cave appended at file 0x92000 (unused sector-9 tail), pool-free (movw/movt/adr/bl).
#   * flash-writer is called in task context with the UPG file already f_read; opening a
#     second FIL sequentially is assumed safe (FatFs non-reentrant) — confirm on bench.
BASE = 0x08020000
F_OPEN, F_WRITE, F_CLOSE = 0x0363E0, 0x0366C8, 0x0368E8
F_SYNC = 0x03685A                  # f_close calls this internally (dir-entry size flush)
WR_ENTRY = 0x910AC                 # file offset of flash-writer entry
CAVE_OFF = 0x92000                 # file offset of appended cave
FIL, BW, FLAG = 0x2003F000, 0x2003F230, 0x2003F234
MAGIC = 0x2003D00D
BOOT_BASE, BOOT_LEN = 0x08000000, 0x20000

def _imm16(h1base, rd, imm):
    imm4 = (imm >> 12) & 0xF; i = (imm >> 11) & 1; imm3 = (imm >> 8) & 7; imm8 = imm & 0xFF
    return struct.pack('<HH', h1base | (i << 10) | imm4, (imm3 << 12) | (rd << 8) | imm8)

def movw(rd, imm): return _imm16(0xF240, rd, imm)
def movt(rd, imm): return _imm16(0xF2C0, rd, imm)
def movs(rd, imm8): return struct.pack('<H', 0x2000 | (rd << 8) | (imm8 & 0xFF))
def _branch(h1base, h2base, addr, target):
    off = target - (addr + 4)
    if not (-(1 << 24) <= off < (1 << 24)): raise ValueError("branch out of range")
    S = (off >> 24) & 1; I1 = (off >> 23) & 1; I2 = (off >> 22) & 1
    J1 = I1 ^ S ^ 1; J2 = I2 ^ S ^ 1
    imm10 = (off >> 12) & 0x3FF; imm11 = (off >> 1) & 0x7FF
    return struct.pack('<HH', h1base | (S << 10) | imm10, h2base | (J1 << 13) | (J2 << 11) | imm11)
def bl(addr, target): return _branch(0xF000, 0xD000, addr, target)
def bw(addr, target): return _branch(0xF000, 0x9000, addr, target)
def bcond(addr, target, cond):
    off = (target - (addr + 4)) >> 1
    if not (-128 <= off < 128): raise ValueError("cond branch out of range")
    return struct.pack('<H', 0xD000 | (cond << 8) | (off & 0xFF))
def ldr_imm(rd, rn, off=0): return struct.pack('<H', 0x6800 | ((off >> 2) << 6) | (rn << 3) | rd)
def str_imm(rd, rn, off=0): return struct.pack('<H', 0x6000 | ((off >> 2) << 6) | (rn << 3) | rd)
def cmp_reg(rn, rm): return struct.pack('<H', 0x4280 | (rm << 3) | rn)
def pushw(regs, lr):  # regs bitmask r0..r12
    return struct.pack('<HH', 0xE92D, ((1 if lr else 0) << 14) | regs)
def popw(regs, lr):
    return struct.pack('<HH', 0xE8BD, ((1 if lr else 0) << 14) | regs)

def build_dump_hook():
    """Return (patches, append) for the experimental dump hook."""
    cave = bytearray(); ca = BASE + CAVE_OFF
    def emit(b): cave.extend(b)
    emit(pushw(0x1FFF, True))                       # push.w {r0-r12,lr}
    a = ca + len(cave); emit(movw(0, FLAG & 0xFFFF)); emit(movt(0, FLAG >> 16))
    emit(ldr_imm(1, 0))                             # ldr r1,[r0]  (flag)
    emit(movw(2, MAGIC & 0xFFFF)); emit(movt(2, MAGIC >> 16))
    emit(cmp_reg(1, 2))
    beq_skip = ca + len(cave); emit(b'\x00\xd0')    # beq skip (patched below)
    emit(str_imm(2, 0))                             # str r2,[r0]  flag=MAGIC
    # f_open(&FIL, path, FA_CREATE_ALWAYS|FA_WRITE = 0x0A)
    emit(movw(0, FIL & 0xFFFF)); emit(movt(0, FIL >> 16))
    adr_pos = ca + len(cave); emit(b'\x00\xa0')     # adr r1,path (patched below)
    emit(movs(2, 0x0A))
    emit(bl(ca + len(cave), BASE + F_OPEN))
    emit(struct.pack('<H', 0x2800))                 # cmp r0,#0
    bne_skip = ca + len(cave); emit(b'\x00\xd1')    # bne skip (patched)
    # f_write(&FIL, BOOT_BASE, BOOT_LEN, &BW)
    emit(movw(0, FIL & 0xFFFF)); emit(movt(0, FIL >> 16))
    emit(movw(1, BOOT_BASE & 0xFFFF)); emit(movt(1, BOOT_BASE >> 16))
    emit(movw(2, BOOT_LEN & 0xFFFF)); emit(movt(2, BOOT_LEN >> 16))
    emit(movw(3, BW & 0xFFFF)); emit(movt(3, BW >> 16))
    emit(bl(ca + len(cave), BASE + F_WRITE))
    # f_close(&FIL)
    emit(movw(0, FIL & 0xFFFF)); emit(movt(0, FIL >> 16))
    emit(bl(ca + len(cave), BASE + F_CLOSE))
    skip = ca + len(cave)
    emit(popw(0x1FFF, True))                        # pop.w {r0-r12,lr}
    emit(pushw(0x0FF0, True))                       # push.w {r4-r11,lr} (orig prologue)
    emit(bw(ca + len(cave), BASE + WR_ENTRY + 4))   # b.w flash-writer+4
    path_off = len(cave); cave.extend(b'0:/BOOT.BIN\x00')
    # patch branches
    struct.pack_into('<H', cave, beq_skip - ca, 0xD000 | (((skip - (beq_skip + 4)) >> 1) & 0xFF))
    struct.pack_into('<H', cave, bne_skip - ca, 0xD100 | (((skip - (bne_skip + 4)) >> 1) & 0xFF))
    adr_target = ca + path_off
    imm8 = (adr_target - ((adr_pos + 4) & ~3)) >> 2
    struct.pack_into('<H', cave, adr_pos - ca, 0xA100 | (imm8 & 0xFF))   # adr r1,path
    # hook: overwrite flash-writer entry prologue with b.w cave
    hook = bw(BASE + WR_ENTRY, ca)
    return [(WR_ENTRY, hook)], (CAVE_OFF, bytes(cave))

def verify_cave(cave):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        print("  [cave] capstone unavailable — run under nix-shell to verify"); return
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    print("  [cave] disassembly (encoding verification):")
    for i in md.disasm(cave, BASE + CAVE_OFF):
        print(f"    0x{i.address:08x}: {i.mnemonic:9s} {i.op_str}")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('stock'); ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--patch', action='append', default=[], help='OFF:HEXBYTES (repeatable)')
    ap.add_argument('--dump-hook', action='store_true', help='append EXPERIMENTAL bootloader-dump cave')
    ap.add_argument('--verify-only', action='store_true')
    args = ap.parse_args()
    raw = open(args.stock, 'rb').read()
    if args.verify_only:
        dec = xor_crypt(raw, derive_key(raw)); check_integrity(dec, 'input'); return
    patches = []
    for p in args.patch:
        off, hx = p.split(':', 1); patches.append((int(off, 0), bytes.fromhex(hx)))
    append = None
    if args.dump_hook:
        print("== EXPERIMENTAL dump hook (bench-verify before flashing; REPORT §5.13) ==")
        hp, append = build_dump_hook(); patches += hp
        verify_cave(append[1])
    out = build(raw, patches, append)
    open(args.out, 'wb').write(out)
    print(f"  wrote {args.out} ({len(out)} bytes)")
    if not patches and append is None:
        print(f"  round-trip byte-identical to stock: {out == raw}")

if __name__ == '__main__':
    main()
