#!/usr/bin/env bash
# acq/uart_dump.sh — FALLBACK (probe-free): STM32F4 built-in system bootloader, UART.
# Enter: BOOT0=1 at reset (BOOT1/PB2 don't-care). ST system bootloader (AN2606) on
# USART1 PA9(TX)/PA10(RX) is the usual first try for F427/F429; exact UART per AN2606.
# Bridge: ESP32-S3 flashed as a 3.3 V USB-CDC<->UART bridge, or a dedicated 3.3 V
# USB-UART (CP2102/FT232). A 5 V adapter (Arduino Mega) risks the 3.3 V MCU — avoid.
#
# READ-ONLY: stm32flash -r (read) + -S (range) + bare-port device-info probe ONLY.
# NEVER -k/-j/-u/-o/-e/-w/-g (unlock/protect/erase/write/execute). -k disables RDP
# and MASS-ERASES — destroys the bootloader. Requires RDP0 (read blocked at RDP1).
# Usage: ./uart_dump.sh [port] [output_dir]   (default port /dev/ttyACM0, dir acq/dump)
# Env:   BAUD -> baud rate (default 115200; stm32flash autobauds via INIT 0x7F).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-/dev/ttyACM0}"
OUT="${2:-$HERE/dump}"; mkdir -p "$OUT"; cd "$OUT"
BAUD="${BAUD:-115200}"
echo "[acq] UART dump via $PORT @ $BAUD (BOOT0=1, system bootloader). READ-ONLY."
nix-shell -p stm32flash --run "
  set -o pipefail
  echo '=== device-info probe (read-only; reports chip id / flash size / RDP) ==='
  stm32flash -b $BAUD '$PORT' 2>&1 | tee uart_info.txt || true
  echo '=== dump bootloader 0x08000000:0x20000 ==='
  stm32flash -b $BAUD -r boot.bin -S 0x08000000:0x20000 '$PORT' 2>&1 | tee uart_boot_log.txt
  echo '=== dump full flash 0x08000000:0x100000 ==='
  stm32flash -b $BAUD -r flash_full.bin -S 0x08000000:0x100000 '$PORT' 2>&1 | tee uart_full_log.txt
"
echo "[acq] done. Dumps + logs in $OUT. Verify: python3 $HERE/analyze_boot.py $OUT/boot.bin"
