#!/usr/bin/env bash
# acq/swd_dump.sh — PRIMARY acquisition path: non-destructive SWD flash dump.
# Probe: ESP32-S3 flashed with fl4p/daplink-s3 (USB CMSIS-DAP v2). See README.md.
#
# READ-ONLY. Never unlocks/erases/writes. Bench only: HV side disconnected &
# capacitors discharged; SWD is in the 3.3 V MCU domain (REPORT §5.7).
#
# Wiring: SWDIO=PA13, SWCLK=PA14, GND, NRST (connect-under-reset), 3V3 sense.
# Usage: ./swd_dump.sh [output_dir]          (default: acq/dump)
# Env:   SWD_NO_RESET=1  -> omit NRST / connect-under-reset (if NRST not wired;
#                           less reliable if the app reuses PA13/14 or sleeps).
#        ADAPTER_SPEED   -> SWD clock in kHz (default 1000; lower if unstable).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/dump}"
mkdir -p "$OUT"; cd "$OUT"
SPEED="${ADAPTER_SPEED:-1000}"
if [ "${SWD_NO_RESET:-0}" = "1" ]; then
  RESET_CFG="reset_config none"
else
  RESET_CFG="reset_config srst_only srst_nogate connect_assert_srst"
fi
echo "[acq] SWD dump -> $OUT  (speed ${SPEED} kHz, $RESET_CFG)"
echo "[acq] READ-ONLY: probe-first; refuses to dump if RDP1/2. Never unlock."
nix-shell -p openocd --run "set -o pipefail; openocd \
  -f interface/cmsis-dap.cfg \
  -c 'transport select swd' \
  -c 'adapter speed $SPEED' \
  -f target/stm32f4x.cfg \
  -c '$RESET_CFG' \
  -f '$HERE/swd_dump.tcl' 2>&1 | tee openocd_log.txt"
rc=$?
echo "[acq] openocd exit=$rc. Dumps + openocd_log.txt in $OUT"
echo "[acq] verify: nix-shell -p python3 python3Packages.capstone --run 'python3 $HERE/analyze_boot.py $OUT/boot.bin'"
