/* test_mbedtls_config.h — HOST-TEST-ONLY wrapper around the byte-exact recovered firmware config.
 *
 * The recovered src/mbedtls_config.h is TLS 1.2 CLIENT-only (MBEDTLS_SSL_CLI_C, no SSL_SRV_C): the
 * adapter is the ISO 15118 EVCC *client*; the SECC is the server. That is the faithful firmware
 * config and the firmware build uses it directly (build.sh: -DMBEDTLS_CONFIG_FILE="mbedtls_config.h").
 *
 * test_tls_mbedtls.c drives a REAL client<->server handshake to validate the recovered client config
 * end-to-end. The test harness must therefore act as a SECC server, which needs the mbedTLS server
 * code path. This wrapper includes the recovered config UNCHANGED and adds MBEDTLS_SSL_SRV_C ONLY
 * (no session tickets / cache are enabled, so no extra dependency). The CLIENT under test is still
 * configured exactly like src/v2g_stack.c::v2g_stack_tls_setup — recovered cipher list {0xC023,
 * 0xC025}, authmode 2 (VERIFY_REQUIRED), secp256r1, EtM + EMS, f_rng, ca_store DER -> CA chain — so
 * the handshake validates the recovered config, not a modified one. NOT used by the firmware build. */
#include "mbedtls_config.h"
#define MBEDTLS_SSL_SRV_C   /* test-harness server side only; firmware config stays client-only */