# Vendored third-party libraries (freestanding ARM Cortex-M4 build)

The stock C013 firmware IS lwIP + mbedTLS (the recovered ND6/TCP/crypto addresses are
library symbols). Per the open-source-first directive these layers use the real upstream
libraries, configured to the byte-exact recovered config (see custom_fw/src/mbedtls_config.h
and custom_fw/src/lwipopts.h), rather than hand-rolled reimplementations.

- mbedtls/ : Mbed-TLS/mbedtls tag mbedtls-2.28.9 (2.28 LTS). Only library/ + include/ vendored.
- lwip/    : lwip-tcpip/lwip branch STABLE-2_1_x (2.1.4). Only src/ vendored.

Upstream LICENSE files apply (mbedTLS Apache-2.0; lwIP BSD). Build is freestanding
(-ffreestanding -nostdlib); a tiny libc shim (src/libc_shim.c) + mbedTLS platform calloc/free
hooks + lwIP NO_SYS=1 raw API replace the OS/libc dependencies.
