#!/usr/bin/env python3
"""make_custom_upg.py — wrap a custom app binary into a vendor-bootable, stock-reversible UPG.

Extends the cracked UPG format (REPORT §4.1/§5.13/§5.16, make_service_upg.py) to a WHOLE-APP
replacement. make_service_upg.py preserves the stock entry shell [0x400:0x45E] and only patches
>=0x40A, so it cannot swap in a different app; this builder replaces the entire app region:

  decoded layout: [0:2] key-echo | [2:58] $$header | [58:3EA] discarded prefix
                  | [3EA:400] footer metadata (length@3F2, CRC@3FE) | [400:402] 2 discarded bytes
                  | [402:40A] vector SP+reset | [40A:n-4] app code | [n-4:n] trailer
  transform:      keep stock [0:3EA] (key/header/prefix) + [400:402] (2 discarded bytes) VERBATIM;
                  set [402:] = the custom app binary (vectors + code, linked at 0x08020000);
                  re-seal length@3F2 = filesize-0x404, footer CRC@3FE = MODBUS(dec[3EA:3FE]),
                  trailer dec[n-4:n] = 00 00 + MODBUS(dec[2:n-2]); re-XOR with the stock key.

The boot strips the 0x402 header and installs fw[0x402:] VERBATIM at 0x08020000 (§5.16), then
branches to the app reset vector (§5.15) — so dec[0x402:] == app.bin is exactly what runs.
Boot-time verify = CRC16/MODBUS residue + config additive checksum (§5.15); both CRCs are
recomputed here. Stock recovery is unchanged: SERVICE.UPG (make_service_upg.py STOCK -o ...)
re-flashes the exact stock app; the bootloader (sectors 0-4) is never touched by a MAIN update.

Usage:
  python3 make_custom_upg.py STOCK.UPG custom_fw/app_padded.bin -o CUSTOM.UPG
"""
import struct, argparse
from make_service_upg import modbus, derive_key, xor_crypt, check_integrity

APP_HDR = 0x402                 # boot strips this many bytes; fw[0x402:] installs at 0x08020000
LEN_OFF, FOOT_CRC_OFF = 0x3F2, 0x3FE
FOOT_LO, FOOT_HI = 0x3EA, 0x3FE
APP_BASE, APP_END = 0x08020000, 0x080C0000


def build_custom(stock_raw, app_bin, verbose=True):
    key = derive_key(stock_raw)
    stock_dec = xor_crypt(stock_raw, key)
    if verbose:
        print(f"  key={key.hex()} stock decoded={len(stock_dec)} (0x{len(stock_dec):x}) B")
        check_integrity(stock_dec, 'stock')
    if len(app_bin) < 8:
        raise ValueError("app binary too small — no vector table")
    sp, reset = struct.unpack_from('<II', app_bin, 0)
    if not (APP_BASE <= (reset & ~1) < APP_END) or not (reset & 1):
        raise ValueError(f"app reset vector 0x{reset:08X} not a Thumb address in app flash")
    if verbose:
        print(f"  app vectors: MSP=0x{sp:08X} reset=0x{reset:08X} (handler 0x{reset & ~1:08X})")
    # keep stock key/header/prefix [0:0x402] (footer metadata gets re-sealed below);
    # replace [0x402:] with the custom app (vectors + code).
    body = bytearray(stock_dec[:APP_HDR]) + app_bin
    new = body + b'\x00\x00\x00\x00'        # trailer: 00 00 key-echo + CRC placeholder
    n = len(new)
    struct.pack_into('<I', new, LEN_OFF, n - 0x404)
    struct.pack_into('<H', new, FOOT_CRC_OFF, modbus(new[FOOT_LO:FOOT_HI]))
    struct.pack_into('<H', new, n - 2, modbus(new[2:n - 2]))
    out = xor_crypt(bytes(new), key)
    if verbose:
        print(f"  rebuilt={n} (0x{n:x}) B; length field=0x{n - 0x404:x}")
        rt = bytearray(xor_crypt(out, key))
        check_integrity(rt, 'rebuilt')
        assert bytes(rt[:FOOT_LO]) == bytes(stock_dec[:FOOT_LO]), "key/header/prefix changed!"
        assert bytes(rt[0x400:APP_HDR]) == bytes(stock_dec[0x400:APP_HDR]), "entry 2 bytes changed!"
        assert bytes(rt[APP_HDR:APP_HDR + len(app_bin)]) == app_bin, "app not installed verbatim!"
        print("  verbatim [0:3EA] + entry[400:402] preserved; app verbatim at [402:]: OK")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('stock', help='stock UPG (source of the key + discarded prefix/header)')
    ap.add_argument('app', help='custom app binary (vectors+code, linked at 0x08020000)')
    ap.add_argument('-o', '--out', required=True)
    args = ap.parse_args()
    stock_raw = open(args.stock, 'rb').read()
    app_bin = open(args.app, 'rb').read()
    out = build_custom(stock_raw, app_bin)
    open(args.out, 'wb').write(out)
    print(f"  wrote {args.out} ({len(out)} bytes)")


if __name__ == '__main__':
    main()