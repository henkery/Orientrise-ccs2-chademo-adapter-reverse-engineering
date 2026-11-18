#!/usr/bin/env bash
# acq/dfu_dump.sh — FALLBACK (probe-free): STM32F4 system bootloader USB DFU (DfuSe).
# Enter: BOOT0=1 at reset, USB OTG FS connected. ST DFU VID:PID = 0483:df11.
# NOTE: the app uses USB OTG FS as HOST (USB-A stick). DFU needs DEVICE mode on the
# same port — may not be exposed on a host-only connector. If `dfu-util -l` shows no
# 0483:df11, use the UART path instead. Requires RDP0 (DFU read blocked at RDP1).
#
# READ-ONLY: dfu-util -U (upload = read) + -s addr:len + -a 0 ONLY.
# NEVER -D (download/write) or -s modifiers :unprotect / :mass-erase / :force —
# :unprotect MASS-ERASES (destroys the bootloader).
# Usage: ./dfu_dump.sh [output_dir]   (default acq/dump)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/dump}"; mkdir -p "$OUT"; cd "$OUT"
echo "[acq] USB DFU dump (BOOT0=1, 0483:df11). READ-ONLY."
nix-shell -p dfu-util --run "
  set -o pipefail
  echo '=== list DFU devices (look for 0483:df11) ==='
  dfu-util -l 2>&1 | tee dfu_list.txt || true
  echo '=== upload bootloader 0x08000000:0x20000 ==='
  dfu-util -d 0483:df11 -a 0 -s 0x08000000:0x20000 -U boot.bin 2>&1 | tee dfu_boot_log.txt
  echo '=== upload full flash 0x08000000:0x100000 ==='
  dfu-util -d 0483:df11 -a 0 -s 0x08000000:0x100000 -U flash_full.bin 2>&1 | tee dfu_full_log.txt
"
echo "[acq] done. Dumps + logs in $OUT. Verify: python3 $HERE/analyze_boot.py $OUT/boot.bin"
