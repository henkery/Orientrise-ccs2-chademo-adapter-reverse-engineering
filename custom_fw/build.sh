#!/usr/bin/env bash
# build.sh — build the inert custom-app skeleton into a raw flash image (app.bin).
# Runs the ARM cross-toolchain + python under nix-shell (NixOS). Produces:
#   app.elf / app.map  — linked at 0x08020000 (linker.ld, REPORT §5.19)
#   app.bin            — raw binary (vectors + code), objcopy -O binary
#   app_padded.bin     — app.bin padded to 128 KB (sector 5) with 0xFF, for UPG wrapping
# No hardware is touched. Wrap app_padded.bin into a bootable UPG with make_custom_upg.py.
set -euo pipefail
cd "$(dirname "$0")"

nix-shell -p gcc-arm-embedded python3 --run '
  set -euo pipefail
  arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -O2 -ffreestanding -nostdlib \
    -Wall -Wextra -Isrc -ffunction-sections -fdata-sections \
    -T linker.ld startup.s main.c src/rcc.c src/gpio.c src/tick.c src/can.c src/chademo.c \
    src/spi4.c src/nv_cal.c src/adc.c src/hv.c src/charge_stm.c -o app.elf -lgcc \
    -Wl,-Map=app.map -Wl,--gc-sections -Wl,--build-id=none
  arm-none-eabi-objcopy -O binary app.elf app.bin
  echo "--- size ---"
  arm-none-eabi-size app.elf
  echo "--- verify vectors + pad ---"
  python3 verify_pad.py
'