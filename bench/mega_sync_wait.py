#!/usr/bin/env python3
"""mega_sync_wait.py — catch an old Arduino Mega bootloader by streaming STK_GET_SYNC continuously
while the user holds-then-releases the physical RESET button.

avrdude's discrete reset+sync attempts miss the bootloader's short sync-wait window. Here we open
the port and send STK_GET_SYNC (0x30 0x20) every ~30ms for a fixed duration; the user holds RESET
(chip held in reset), then releases it — the bootloader starts and immediately answers the next
sync probe with STK_INSYNC 0x14 + STK_OK 0x10. Non-destructive.

  sg dialout -c 'nix-shell -p python3 python3Packages.pyserial --run \
      "python3 bench/mega_sync_wait.py /dev/ttyUSB2 57600 25"'

Args: PORT BAUD DURATION_SECONDS. Exit 0 on sync (prints baud), 1 on timeout.
"""
import sys
import time

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB2"
BAUD = int(sys.argv[2]) if len(sys.argv) > 2 else 57600
DUR = float(sys.argv[3]) if len(sys.argv) > 3 else 25.0


def main():
    s = serial.Serial(PORT, BAUD, timeout=0.05)
    # leave DTR/RTS idle-high (no auto-reset); the physical button controls reset.
    s.dtr = True
    s.rts = True
    print(f"streaming STK_GET_SYNC at {BAUD} for {DUR}s — HOLD then RELEASE the Mega RESET button")
    end = time.time() + DUR
    n = 0
    while time.time() < end:
        s.reset_input_buffer()
        s.write(bytes([0x30, 0x20]))
        s.flush()
        resp = s.read(2)
        n += 1
        if resp == bytes([0x14, 0x10]):
            print(f"SYNC OK after {n} probes at {BAUD} baud")
            s.close()
            return 0
        time.sleep(0.03)
    print(f"no sync in {DUR}s ({n} probes) at {BAUD}")
    s.close()
    return 1


if __name__ == "__main__":
    sys.exit(main())