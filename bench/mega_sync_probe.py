#!/usr/bin/env python3
"""mega_sync_probe.py — find an old Arduino Mega (ATmega1280/2560) bootloader by precise
DTR-reset + STK500v1 sync, sweeping baud rates.

The old Mega's FTDI FT232RL couples DTR (and/or RTS) through a 100nF cap to the MCU RESET pin:
only the *edge* pulses reset (the cap blocks DC). avrdude's auto-reset sometimes misses the
bootloader's short sync-wait window; here we create the edge ourselves and send STK_GET_SYNC
(0x30 0x20) immediately, expecting STK_INSYNC 0x14 + STK_OK 0x10. Non-destructive (no flash write).

  sg dialout -c 'nix-shell -p python3 python3Packages.pyserial --run \
      "python3 bench/mega_sync_probe.py /dev/ttyUSB2"'

Exit 0 + prints the baud if a bootloader answers; exit 1 if none. Use the reported baud with
avrdude -c arduino -b <baud> (1280) / -c wiring (2560) to flash.
"""
import sys
import time

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB2"
# old Mega1280 stock = 57600; clones/old bootloaders may be 19200/115200/9600.
BAUDS = [57600, 19200, 115200, 9600, 38400, 4800]


def try_sync(baud, attempts=8):
    for a in range(attempts):
        try:
            s = serial.Serial(PORT, baud, timeout=0.25)
        except Exception as e:
            print(f"  open fail: {e}")
            return False
        # idle high, then falling edge on DTR+RTS -> cap-coupled RESET pulse.
        s.dtr = True
        s.rts = True
        time.sleep(0.05)
        s.dtr = False
        s.rts = False
        time.sleep(0.06)            # MCU comes out of reset + bootloader enters sync-wait
        s.reset_input_buffer()
        s.write(bytes([0x30, 0x20]))  # STK_GET_SYNC + CRC_EOP
        s.flush()
        resp = s.read(2)
        s.close()
        if resp == bytes([0x14, 0x10]):
            print(f"  SYNC OK at baud {baud} (attempt {a + 1})")
            return True
        print(f"  baud {baud} attempt {a + 1}: resp={resp.hex() if resp else '(none)'}")
        time.sleep(0.08)
    return False


def main():
    print(f"probing {PORT} for an AVR bootloader (DTR-reset + STK500v1 sync)")
    for b in BAUDS:
        print(f"=== baud {b} ===")
        if try_sync(b):
            print(f"FOUND bootloader at {b} baud")
            return 0
    print("No bootloader sync at any baud.")
    return 1


if __name__ == "__main__":
    sys.exit(main())