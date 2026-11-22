#!/usr/bin/env bash
# build.sh — build the custom adapter app (vendored lwIP 2.1.x + mbedTLS 2.28 + recovered glue)
# into a raw flash image (app.bin). Runs the ARM cross-toolchain + python under nix-shell (NixOS).
# Produces app.elf / app.map (linked at 0x08020000, linker.ld §5.19), app.bin (objcopy -O binary),
# app_padded.bin (verify_pad.py, 128 KB sector 5). Wrap into a bootable UPG with make_custom_upg.py.
#
# Library pivot: the live IPv6/ND6/TCP/UDP + TLS/crypto stack is the REAL upstream lwIP + mbedTLS
# (the stock C013 firmware IS these libraries), configured byte-exact via src/lwipopts.h +
# src/mbedtls_config.h. src/libc_shim.c provides the freestanding mem/str + lwIP port; the mbedTLS
# heap is MBEDTLS_MEMORY_BUFFER_ALLOC_C over a static pool. No hardware is touched.
set -euo pipefail
cd "$(dirname "$0")"

# Re-exec under nix-shell so the cross-toolchain + python are on PATH (NixOS). Use a dedicated
# guard (IN_NIX_SHELL may already be set in the ambient environment).
if [ -z "${CUSTOM_FW_BUILD_NIX:-}" ]; then
  export CUSTOM_FW_BUILD_NIX=1
  exec nix-shell -p gcc-arm-embedded python3 --run "bash '$0'"
fi

CFLAGS=(-mcpu=cortex-m4 -mthumb -ffreestanding -nostdlib -fno-builtin
  -fno-tree-loop-distribute-patterns -ffunction-sections -fdata-sections -w
  -DMBEDTLS_CONFIG_FILE='"mbedtls_config.h"'
  -Isrc -Isrc/usb -Ithird_party/tinyusb/src
  -Ithird_party/mbedtls/include -Ithird_party/lwip/src/include)

# Recovered glue + safe-bootstrap app modules (nd6.c retired -> lwIP nd6; tcp/tls/crypto/ecc/x509
# retired -> lwIP TCP + mbedTLS). v2g_stack/hw_rng/libc_shim are the new library-integration layer.
APP=(startup.s main.c
  src/rcc.c src/gpio.c src/tick.c src/can.c src/chademo.c src/spi4.c src/nv_cal.c src/adc.c
  src/hv.c src/charge_stm.c src/current_ctrl.c src/current_ramp.c src/qca7005.c src/v2gtp.c src/slac.c src/cp.c
  src/cp_capture.c src/cp_adc.c src/sdp.c src/din70121.c src/exi.c src/din_session.c
  src/v2g_net.c src/v2g_stack.c src/hw_rng.c src/libc_shim.c src/ca_store.c src/ccs2.c
  src/revert.c src/revert_stage.c
  src/usb/cdc_proto.c src/usb/usb_hw.c src/usb/usb_cdc.c src/usb/usb_descriptors.c)

# TinyUSB (vendored MIT subset, master 490eb4e): device CDC on the Synopsys dwc2 OTG_FS port. Config
# in src/usb/tusb_config.h; freestanding CMSIS shim src/usb/stm32f4xx.h. --gc-sections drops unused.
TUSB=(third_party/tinyusb/src/tusb.c
  third_party/tinyusb/src/common/tusb_fifo.c
  third_party/tinyusb/src/device/usbd.c
  third_party/tinyusb/src/class/cdc/cdc_device.c
  third_party/tinyusb/src/portable/synopsys/dwc2/dcd_dwc2.c
  third_party/tinyusb/src/portable/synopsys/dwc2/dwc2_common.c)

# lwIP 2.1.x subset: NO_SYS=1 raw API, IPv6 + TCP + UDP + ICMPv6 + ND6 + frag/reass + ethernet.
LWIP=(third_party/lwip/src/core/init.c third_party/lwip/src/core/def.c
  third_party/lwip/src/core/mem.c third_party/lwip/src/core/memp.c
  third_party/lwip/src/core/pbuf.c third_party/lwip/src/core/netif.c
  third_party/lwip/src/core/ip.c third_party/lwip/src/core/tcp.c
  third_party/lwip/src/core/tcp_in.c third_party/lwip/src/core/tcp_out.c
  third_party/lwip/src/core/udp.c third_party/lwip/src/core/timeouts.c
  third_party/lwip/src/core/stats.c third_party/lwip/src/core/inet_chksum.c
  third_party/lwip/src/core/ipv6/ip6.c third_party/lwip/src/core/ipv6/ip6_frag.c
  third_party/lwip/src/core/ipv6/nd6.c third_party/lwip/src/core/ipv6/icmp6.c
  third_party/lwip/src/core/ipv6/ethip6.c third_party/lwip/src/core/ipv6/ip6_addr.c
  third_party/lwip/src/core/ipv6/inet6.c third_party/lwip/src/netif/ethernet.c)

# Two optimization groups (size budget: app.bin must fit sector 5 = 128 KB, verify_pad.py):
#  - Custom modules at -O2: verify_ccs2.py asserts their constant codegen (cp_capture/cp_adc TIM4/
#    ADC3 immediates + the x6600//32760 multiply-magic, din70121 pow10 table) — keep that codegen.
#  - Vendored libraries (TinyUSB + lwIP + mbedTLS) at -Os: verify_ccs2.py checks their PRESENCE only,
#    so size-optimize them to recover the ~17 KB the CDC stack adds. --gc-sections drops unused.
OBJDIR=build/obj
rm -rf "$OBJDIR"; mkdir -p "$OBJDIR"
OBJS=()
compile() {                       # $1 = -O level; rest = sources
  local opt="$1"; shift
  local src obj
  for src in "$@"; do
    obj="$OBJDIR/$(printf '%s' "$src" | tr '/' '_').o"
    arm-none-eabi-gcc "${CFLAGS[@]}" "$opt" -c "$src" -o "$obj"
    OBJS+=("$obj")
  done
}
compile -O2 "${APP[@]}"
compile -Os "${TUSB[@]}" "${LWIP[@]}" third_party/mbedtls/library/*.c

arm-none-eabi-gcc "${CFLAGS[@]}" -T linker.ld "${OBJS[@]}" -o app.elf -lgcc \
  -Wl,-Map=app.map -Wl,--gc-sections -Wl,--build-id=none
arm-none-eabi-objcopy -O binary app.elf app.bin
echo "--- size ---"
arm-none-eabi-size app.elf
echo "--- verify vectors + pad ---"
python3 verify_pad.py
