#!/usr/bin/env python3
"""bench/uart_probe.py — boot UART recovery probe / XMODEM-1K re-flash for the adapter.

The boot (sectors 0-4, untouched by a MAIN update) has an app-independent serial recovery
path (REPORT §5.15b): USART1 @ 230400 8N1. >=4 consecutive 0x55/0x75 sync bytes during the
boot decision window force XMODEM-1K/CRC intake BEFORE any app-validity check. The intake
prints device info, then receives a raw UPG via XMODEM-1K/CRC, stages it to the SPI pool,
XOR+CRC decodes, installs verbatim + rebuilds the boot config, and resets.

Modes:
  listen  — capture UART output (reset the adapter during the window). A normal boot launches
            the app silently; device-info text + 'C' (0x43) bytes mean the boot fell into
            recovery intake (invalid app/config, or sync seen).
  sync    — continuously send 0x55 while listening: forces recovery intake at reset and captures
            the device-info print + the XMODEM 'C' poll. Run this, then reset the adapter.
  send    — XMODEM-1K/CRC upload of a raw UPG (SERVICE.UPG = revert to stock; CUSTOM.UPG = custom).
            Recovery must already be active (boot polling 'C'). The boot installs + rebuilds config.

Wiring: bridge TX -> adapter PA10 (USART1_RX), bridge RX -> adapter PA9 (USART1_TX), GND common.
3.3 V levels only. Bench: HV disconnected, bulk caps discharged.

Usage (NixOS):
  nix-shell -p python3 python3Packages.pyserial --run 'python3 bench/uart_probe.py listen --seconds 12'
  nix-shell -p python3 python3Packages.pyserial --run 'python3 bench/uart_probe.py sync --seconds 12'
  nix-shell -p python3 python3Packages.pyserial --run 'python3 bench/uart_probe.py send SERVICE.UPG'
  ... --port /dev/ttyUSB0 (default) --baud 230400 (default)
"""
import argparse
import sys
import time

DEFAULT_PORT = "/dev/ttyUSB0"
DEFAULT_BAUD = 230400
SOH, STX, EOT, ACK, NAK, CAN, C_CRC = 0x01, 0x02, 0x04, 0x06, 0x15, 0x18, 0x43


def crc16_xmodem(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return crc


def open_port(port, baud, timeout=0.05):
    import serial
    print(f"[uart] opening {port} @ {baud} 8N1")
    return serial.Serial(port, baud, timeout=timeout, write_timeout=2)


def show(data, t0):
    if not data:
        return
    hexs = " ".join(f"{b:02x}" for b in data)
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    print(f"[uart +{time.time()-t0:6.2f}s] {len(data):4d}B  {asc}")
    print(f"                 hex: {hexs}")


def do_loopback(ser, seconds):
    print(f"[uart] LOOPBACK {seconds}s — jumper the bridge TX->RX (adapter DISCONNECTED). "
          "Verifies the CH340 + port + baud independently of the adapter.")
    pat = bytes([0x55, 0xAA, 0x00, 0xFF, 0x43, 0x06, 0x15, 0x7E])
    t0 = time.time()
    sent = 0
    matched = 0
    next_send = 0.0
    while time.time() - t0 < seconds:
        now = time.time() - t0
        if now >= next_send:
            ser.write(pat)
            ser.flush()
            sent += len(pat)
            next_send = now + 0.1
        data = ser.read(256)
        if data:
            matched += len(data)
            show(data, t0)
    print(f"[uart] loopback: sent {sent} B, received {matched} B. "
          + ("ECHO OK — bridge/port/baud good." if matched >= sent * 0.8
             else "NO/ECHO LOSS — check TX->RX jumper, port, driver, baud."))


def do_listen(ser, seconds):
    print(f"[uart] LISTEN {seconds}s — RESET / power-cycle the adapter NOW. "
          "(device-info text + 'C'=0x43 => boot in recovery; silence => app launched)")
    t0 = time.time()
    while time.time() - t0 < seconds:
        data = ser.read(256)
        show(data, t0)
    print("[uart] listen done")


def do_sync(ser, seconds):
    print(f"[uart] SYNC {seconds}s — sending 0x55 stream; RESET the adapter NOW to force recovery.")
    t0 = time.time()
    burst = bytes([0x55]) * 64
    next_send = 0.0
    while time.time() - t0 < seconds:
        now = time.time() - t0
        if now >= next_send:
            try:
                ser.write(burst)
                ser.flush()
            except Exception as e:
                print(f"[uart] write err: {e}")
            next_send = now + 0.05
        data = ser.read(256)
        show(data, t0)
        if data and (C_CRC in data):
            print("[uart] *** 'C' (0x43) seen — XMODEM-CRC intake ACTIVE. Ready for 'send'. ***")
    print("[uart] sync done")


def wait_for(ser, want, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        b = ser.read(1)
        if b:
            if b[0] in want:
                return b[0]
            # ignore stray device-info text bytes while waiting for the poll
    return None


def xmodem_upload(ser, data):
    """XMODEM-1K/CRC upload assuming the receiver is active (polling 'C'). Sends block 1 at once."""
    n = len(data)
    block = 1
    off = 0
    t0 = time.time()
    while off < n:
        chunk = data[off:off + 1024]
        if len(chunk) < 1024:
            chunk = chunk + bytes([0x1A]) * (1024 - len(chunk))   # XMODEM pad
        crc = crc16_xmodem(chunk)
        pkt = bytes([STX, block & 0xFF, (255 - block) & 0xFF]) + chunk + bytes([crc >> 8, crc & 0xFF])
        ok = False
        for attempt in range(10):
            ser.write(pkt)
            ser.flush()
            r = wait_for(ser, {ACK, NAK, CAN, C_CRC}, 5)
            if r == ACK:
                ok = True
                break
            if r == CAN:
                sys.exit("[uart] receiver CANCELLED (CAN)")
            # NAK or 'C' (re-poll) -> retry same block
        if not ok:
            sys.exit(f"[uart] block {block} not ACKed after retries — aborting (boot keeps current app)")
        off += 1024
        block += 1
        if block % 16 == 0 or off >= n:
            print(f"[uart]   {min(off,n)}/{n} B  block {block-1}  {min(off,n)/1024/max(time.time()-t0,1e-6):.1f} KB/s")
    # end of transmission
    for attempt in range(10):
        ser.write(bytes([EOT]))
        ser.flush()
        r = wait_for(ser, {ACK, NAK, CAN}, 5)
        if r == ACK:
            print(f"[uart] EOT ACKed — {n} B sent in {time.time()-t0:.1f}s. Boot installs + rebuilds config, "
                  "then resets. Wait ~10 s for the new app to launch.")
            return
        if r == CAN:
            sys.exit("[uart] receiver CANCELLED at EOT")
    sys.exit("[uart] EOT not ACKed — install may not have completed; check the device.")


def do_send(ser, path):
    data = open(path, "rb").read()
    print(f"[uart] XMODEM-1K/CRC send {path} ({len(data)} B). Waiting for boot 'C' poll (recovery must be active)...")
    r = wait_for(ser, {C_CRC, NAK}, 30)
    if r is None:
        sys.exit("[uart] no 'C'/NAK poll — recovery not active. Use 'flash' (sync+send) or 'sync' + reset first.")
    if r != C_CRC:
        sys.exit("[uart] receiver wants checksum mode; this tool sends CRC16. Re-run sync to get 'C'.")
    print(f"[uart] receiver poll = 0x{r:02x} (CRC mode)")
    xmodem_upload(ser, data)


def do_flash(ser, path, seconds):
    """Stream 0x55 sync to force recovery at reset, then upload on the boot's first 'C' poll.
    Holds the port continuously: the boot intake times out a few seconds after the sync stream
    stops, so a separate sync->send handoff (with a process-restart gap) loses the window.
    The 'C' (0x43) detector is GATED on the boot banner ('STM32-BOOT'): a stable custom app prints
    hex heartbeats whose 'C' nibble is also 0x43, so an ungated detector false-triggers an upload
    against the running app (which never ACKs). Only a real boot banner arms the 'C' watch."""
    data = open(path, "rb").read()
    print(f"[uart] FLASH {path} ({len(data)} B) — streaming 0x55 sync; RESET the adapter NOW. "
          "Upload starts on the boot banner + first 'C' poll. Do NOT reset during the upload.")
    t0 = time.time()
    burst = bytes([0x55]) * 64
    next_send = 0.0
    next_rst = 0.0
    boot_seen = False
    tail = b""
    while time.time() - t0 < seconds:
        now = time.time() - t0
        if now >= next_send:
            try:
                ser.write(burst)
                ser.flush()
            except Exception as e:
                print(f"[uart] write err: {e}")
            next_send = now + 0.05
        # Hands-free reset: while no boot yet, periodically send the app's "RST" command. The stable
        # app resets into boot, which catches the continuing 0x55 sync -> recovery. Stop once boot is
        # seen so stray "RST" bytes cannot corrupt the XMODEM upload.
        if not boot_seen and now >= next_rst:
            try:
                ser.write(b"RST")
                ser.flush()
            except Exception as e:
                print(f"[uart] rst write err: {e}")
            next_rst = now + 2.0
        rx = ser.read(256)
        if rx:
            show(rx, t0)
            tail = (tail + rx)[-512:]
            if not boot_seen:
                if b"STM32-BOOT" in tail:
                    boot_seen = True
                    tail = tail.split(b"STM32-BOOT", 1)[1]   # ignore any app 'C' nibble before boot
                    print("[uart] boot banner seen — arming 'C' watch")
                else:
                    continue
            if C_CRC in tail:
                print("[uart] *** boot 'C' seen — starting XMODEM upload immediately ***")
                xmodem_upload(ser, data)
                print("[uart] upload done — listening 25s for boot install + app init trace...")
                t1 = time.time()
                while time.time() - t1 < 25:
                    rx2 = ser.read(256)
                    if rx2:
                        show(rx2, t1)
                return
    sys.exit("[uart] no boot 'C' within the sync window — reset the adapter during the window and retry.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["loopback", "listen", "sync", "send", "flash"])
    ap.add_argument("file", nargs="?", help="raw UPG for 'send'/'flash' (SERVICE.UPG / CUSTOM.UPG)")
    ap.add_argument("--port", default=DEFAULT_PORT)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--seconds", type=float, default=12)
    args = ap.parse_args()
    if args.mode in ("send", "flash") and not args.file:
        ap.error(f"{args.mode} requires a UPG file")
    ser = open_port(args.port, args.baud)
    try:
        if args.mode == "loopback":
            do_loopback(ser, args.seconds)
        elif args.mode == "listen":
            do_listen(ser, args.seconds)
        elif args.mode == "sync":
            do_sync(ser, args.seconds)
        elif args.mode == "send":
            do_send(ser, args.file)
        elif args.mode == "flash":
            do_flash(ser, args.file, args.seconds)
    finally:
        ser.close()


if __name__ == "__main__":
    main()