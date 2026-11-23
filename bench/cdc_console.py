#!/usr/bin/env python3
"""bench/cdc_console.py — host side of the custom_fw USB device-CDC revert console.

Talks to the adapter once CUSTOM.UPG is installed and the adapter is plugged into this
PC over USB (OTG_FS device mode, PA11/PA12). It enumerates as VID:PID 0xCafe:0x4004,
product "Adapter Revert Console" (a CDC-ACM tty, e.g. /dev/ttyACM0). Protocol is the
firmware's src/usb/cdc_proto.c: CR/LF-terminated, upper-cased line commands.

  PING            -> PONG
  STATUS          -> MODE CMD | MODE UPLOAD
  HELP            -> CMDS: PING STATUS HELP ABORT REVERT <n>
  ABORT           -> ABORTED   (cancel an in-progress upload)
  REVERT <n>      -> READY     (device erases the SPI update pool, then expects n bytes)
                     ... stream exactly n raw UPG bytes ...
                  -> OK reverting  (header re-check + xPAI descriptor written, then reset;
                                    the boot installs the stock app from the pool)

The whole UPG is streamed (never buffered whole on the F4): the device page-programs the
SPI pool as bytes arrive, validates the header on the last byte, writes the xPAI command
LAST, and resets. Brick-safe: a bad/incomplete upload never writes xPAI, so the boot keeps
the current app.

Usage (NixOS — pyserial via nix-shell):
  nix-shell -p python3 python3Packages.pyserial --run 'python3 bench/cdc_console.py ping'
  nix-shell -p python3 python3Packages.pyserial --run 'python3 bench/cdc_console.py status'
  nix-shell -p python3 python3Packages.pyserial --run 'python3 bench/cdc_console.py revert SERVICE.UPG'
  ... --port /dev/ttyACM0   to force a port (default: auto-detect Cafe:4004 / by-id)

Bench safety: Stage-0 only — HV side disconnected, bulk caps discharged. Reverting writes
the SPI update pool + boot xPAI descriptor and resets; it does NOT drive the power stage.
"""
import argparse
import glob
import os
import sys
import time

VID_PID = "cafe:4004"
BY_ID_GLOB = "/dev/serial/by-id/*Adapter_Revert_Console*"
CHUNK = 256            # match the device's 256 B SPI page buffer
INTER_CHUNK_DELAY = 0.002


def detect_port():
    hits = sorted(glob.glob(BY_ID_GLOB))
    if hits:
        return os.path.realpath(hits[0])
    # fall back: scan lsusb for Cafe:4004 and map to a ttyACM via sysfs
    try:
        import subprocess
        out = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        out = ""
    if VID_PID not in out.lower():
        return None
    for tty in sorted(glob.glob("/dev/ttyACM*")):
        base = os.path.basename(tty)
        dev = os.path.realpath(f"/sys/class/tty/{base}/device")
        # walk up to the USB device and read idVendor/idProduct
        d = dev
        for _ in range(6):
            v = os.path.join(d, "idVendor")
            p = os.path.join(d, "idProduct")
            if os.path.exists(v) and os.path.exists(p):
                try:
                    if open(v).read().strip() == "cafe" and open(p).read().strip() == "4004":
                        return tty
                except OSError:
                    pass
                break
            d = os.path.dirname(d)
    return None


def open_port(port):
    import serial
    if port is None:
        port = detect_port()
    if port is None:
        sys.exit("No CDC console found. Plug the adapter in (after flashing CUSTOM.UPG) "
                 "and check `lsusb` for cafe:4004, or pass --port /dev/ttyACMx.")
    print(f"[cdc] opening {port}")
    # CDC-ACM ignores the baud rate; any value works. Short read timeout for line reads.
    return serial.Serial(port, 115200, timeout=0.2, write_timeout=5)


def read_line(ser, timeout):
    """Read one CR/LF-terminated line (device sends '\\r\\n'). Returns str or None."""
    deadline = time.time() + timeout
    buf = bytearray()
    while time.time() < deadline:
        b = ser.read(1)
        if not b:
            continue
        if b in (b"\n", b"\r"):
            if buf:
                return buf.decode("ascii", "replace").strip()
            continue
        buf += b
    return buf.decode("ascii", "replace").strip() if buf else None


def expect(ser, want, timeout):
    line = read_line(ser, timeout)
    if line is None:
        sys.exit(f"[cdc] TIMEOUT waiting for {want!r} (no response)")
    print(f"[cdc] <- {line}")
    if line != want:
        sys.exit(f"[cdc] expected {want!r}, got {line!r}")
    return line


def cmd_line(ser, command, want, timeout=3):
    ser.reset_input_buffer()
    ser.write((command + "\n").encode())
    ser.flush()
    return expect(ser, want, timeout)


def do_ping(ser):
    cmd_line(ser, "PING", "PONG")
    print("[cdc] PING/PONG OK — console alive")


def do_status(ser):
    ser.reset_input_buffer()
    ser.write(b"STATUS\n")
    ser.flush()
    line = read_line(ser, 3)
    print(f"[cdc] <- {line}")
    if line not in ("MODE CMD", "MODE UPLOAD"):
        sys.exit(f"[cdc] unexpected STATUS response: {line!r}")


def do_help(ser):
    ser.reset_input_buffer()
    ser.write(b"HELP\n")
    ser.flush()
    line = read_line(ser, 3)
    print(f"[cdc] <- {line}")


def do_revert(ser, path):
    data = open(path, "rb").read()
    n = len(data)
    if n < 0x404:
        sys.exit(f"[cdc] {path} too small to be a UPG ({n} B)")
    print(f"[cdc] reverting with {path} ({n} B)")
    ser.reset_input_buffer()
    ser.write(f"REVERT {n}\n".encode())
    ser.flush()
    # device erases the SPI pool first (several sectors) -> READY can take a few seconds
    expect(ser, "READY", timeout=20)
    print(f"[cdc] streaming {n} B in {CHUNK} B chunks ...")
    t0 = time.time()
    sent = 0
    while sent < n:
        chunk = data[sent:sent + CHUNK]
        ser.write(chunk)
        ser.flush()
        sent += len(chunk)
        if sent % (CHUNK * 64) == 0 or sent == n:
            pct = 100.0 * sent / n
            print(f"[cdc]   {sent}/{n} B ({pct:.1f}%)  {sent/1024/max(time.time()-t0,1e-6):.1f} KB/s")
        time.sleep(INTER_CHUNK_DELAY)
    # last byte triggers header re-check + xPAI write + reset
    line = read_line(ser, 15)
    print(f"[cdc] <- {line}")
    if line != "OK reverting":
        sys.exit(f"[cdc] revert did NOT complete cleanly (got {line!r}). "
                 "xPAI was NOT written on a bad upload — current app is intact. "
                 "Check the file / retry; do not power-cycle mid-upload.")
    dt = time.time() - t0
    print(f"[cdc] OK reverting — {n} B in {dt:.1f} s. Device is resetting; the boot will "
          "install the stock app from the SPI pool. Wait ~10 s, then re-plug / check the "
          "stock app resumes (USB host stick export returns).")


def do_readback(ser, command):
    """Stage-1 read-only measurement readback (MEAS/CAN/NET/STM). Prints the device's single line."""
    ser.reset_input_buffer()
    ser.write((command + "\n").encode())
    ser.flush()
    line = read_line(ser, 3)
    if line is None:
        sys.exit(f"[cdc] TIMEOUT waiting for {command} readback")
    print(f"[cdc] <- {line}")
    return line


def do_multiline(ser, cmd, first_timeout=0.5):
    """Send a command whose response spans several lines; read until a quiet gap. first_timeout
    covers a slow first line (e.g. QCAMAC polls the modem up to 1 s before printing)."""
    ser.reset_input_buffer()
    ser.write((cmd + "\n").encode())
    ser.flush()
    lines = []
    while True:
        line = read_line(ser, first_timeout if not lines else 0.5)
        if line is None:
            break
        lines.append(line)
        print(f"[cdc] <- {line}")
    if not lines:
        sys.exit(f"[cdc] TIMEOUT waiting for {cmd} readback")
    return lines


def do_caldump(ser):
    """CALDUMP is a 3-line response (summary / validation fields / 17 raw words). Read them all."""
    return do_multiline(ser, "CALDUMP")


def do_fdump(ser, tokens):
    """FDUMP <addr> <len> (hex): multi-line hex dump of external flash. Read all lines."""
    if len(tokens) < 2:
        sys.exit("[cdc] fdump needs <addr> <len> (hex, len<=256)")
    ser.reset_input_buffer()
    ser.write(("FDUMP " + " ".join(tokens) + "\n").encode())
    ser.flush()
    lines = []
    while True:
        line = read_line(ser, 0.5)
        if line is None:
            break
        lines.append(line)
        print(f"[cdc] <- {line}")
    if not lines:
        sys.exit("[cdc] TIMEOUT waiting for FDUMP")
    return lines


def do_injc(ser, tokens):
    """Inject a CAN frame: tokens = [id, dlc, b0..bN] (hex). Device pushes it into the RX ring."""
    if len(tokens) < 2:
        sys.exit("[cdc] injc needs <id> <dlc> [bytes...] (hex)")
    line = "INJC " + " ".join(tokens)
    ser.reset_input_buffer()
    ser.write((line + "\n").encode())
    ser.flush()
    resp = read_line(ser, 3)
    print(f"[cdc] <- {resp}")
    if resp != "OK INJC":
        sys.exit(f"[cdc] CAN inject failed (got {resp!r})")
    print("[cdc] CAN frame injected — send 'can' to read the parsed CHAdeMO fields")


def do_inje(ser, data):
    """Inject a raw Ethernet frame: stream len(data) bytes -> v2g_net_rx_ethernet on the device."""
    n = len(data)
    if n == 0:
        sys.exit("[cdc] inje: empty frame")
    if n > 1536:
        sys.exit(f"[cdc] inje: frame too large ({n} B > 1536 B device buffer)")
    print(f"[cdc] injecting Ethernet frame ({n} B)")
    ser.reset_input_buffer()
    ser.write(f"INJE {n}\n".encode())
    ser.flush()
    expect(ser, "READY", timeout=5)
    sent = 0
    while sent < n:
        chunk = data[sent:sent + CHUNK]
        ser.write(chunk)
        ser.flush()
        sent += len(chunk)
        time.sleep(INTER_CHUNK_DELAY)
    resp = read_line(ser, 5)
    print(f"[cdc] <- {resp}")
    if resp != "OK INJE":
        sys.exit(f"[cdc] Ethernet inject failed (got {resp!r})")
    print("[cdc] Ethernet frame fed to v2g_net_rx_ethernet — send 'net' to read transport state")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["ping", "status", "help", "revert", "abort",
                                        "meas", "can", "net", "stm", "caldump", "calscan",
                                        "calfind", "fdump", "plc", "qca", "qcamac", "injc", "inje"])
    ap.add_argument("file", nargs="?", help="UPG file for 'revert' / raw frame file for 'inje'")
    ap.add_argument("tokens", nargs="*", help="injc: <id> <dlc> [b0..bN] (hex)")
    ap.add_argument("--hex", help="inje: raw frame as a hex string (instead of a file)")
    ap.add_argument("--port", help="serial port (default: auto-detect cafe:4004)")
    args = ap.parse_args()
    if args.command == "revert" and not args.file:
        ap.error("revert requires a UPG file (e.g. SERVICE.UPG)")
    if args.command == "inje" and not (args.file or args.hex):
        ap.error("inje requires a frame file or --hex <hexstring>")
    ser = open_port(args.port)
    try:
        if args.command == "ping":
            do_ping(ser)
        elif args.command == "status":
            do_status(ser)
        elif args.command == "help":
            do_help(ser)
        elif args.command == "abort":
            cmd_line(ser, "ABORT", "ABORTED")
        elif args.command == "revert":
            do_revert(ser, args.file)
        elif args.command in ("meas", "can", "net", "stm", "calscan"):
            do_readback(ser, args.command.upper())
        elif args.command == "caldump":
            do_caldump(ser)
        elif args.command == "calfind":
            do_multiline(ser, "CALFIND")
        elif args.command == "plc":
            do_multiline(ser, "PLC")
        elif args.command == "qca":
            do_multiline(ser, "QCA")
        elif args.command == "qcamac":
            do_multiline(ser, "QCAMAC", first_timeout=2.0)
        elif args.command == "fdump":
            do_fdump(ser, ([args.file] if args.file else []) + args.tokens)
        elif args.command == "injc":
            # argparse fills the optional 'file' positional first; reassemble the full token list.
            toks = ([args.file] if args.file else []) + args.tokens
            do_injc(ser, toks)
        elif args.command == "inje":
            data = bytes.fromhex(args.hex) if args.hex else open(args.file, "rb").read()
            do_inje(ser, data)
    finally:
        ser.close()


if __name__ == "__main__":
    main()