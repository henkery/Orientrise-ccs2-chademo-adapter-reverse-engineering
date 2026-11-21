/* mbedtls_config.h — minimal Mbed-TLS 2.28 config for the Orientrise CCS2 adapter app.
 * Byte-exact match to the recovered C013 TLS/crypto config (REPORT §5.9, Agent L/M,
 * analyze95/96): TLS 1.2 CLIENT only, EtM + EMS, P_SHA256 PRF, ciphersuites
 * {0xC023 ECDHE-ECDSA-AES128-CBC-SHA256, 0xC025 ECDH-ECDSA-AES128-CBC-SHA256},
 * curve secp256r1 ONLY, sig_hashes {SHA256,SHA224,MD5} (NO SHA1), AES BE ROM tables,
 * max record content 0x2000 (8192). The stock RNG is the STM32 HW-RNG (0x50060800),
 * NOT ctr_drbg — so entropy/DRBG modules are OFF and a custom f_rng is wired by the glue.
 * Freestanding: no FS/net/time; heap via MBEDTLS_MEMORY_BUFFER_ALLOC_C over a static pool.
 * Selected with -DMBEDTLS_CONFIG_FILE='"mbedtls_config.h"'. */
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* ---- system / platform (freestanding Cortex-M4, little-endian, no libc/OS) ---- */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C      /* static-pool calloc/free (no libc heap) */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
/* no MBEDTLS_HAVE_TIME / HAVE_TIME_DATE: x509 skips validity-period check (bench certs) */
/* no MBEDTLS_FS_IO / NET_C / TIMING_C / THREADING_C / DEBUG_C / ERROR_C / SELF_TEST */

/* ---- record layer: TLS 1.2 client, EtM + EMS, 8192-byte content (recovered 0x2000) ---- */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_ENCRYPT_THEN_MAC       /* recovered config bit9 (orr #0x600) */
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET /* recovered config bit10 */
#define MBEDTLS_SSL_IN_CONTENT_LEN  8192
#define MBEDTLS_SSL_OUT_CONTENT_LEN 8192
#define MBEDTLS_SSL_MAX_CONTENT_LEN 8192
/* client-only, no renegotiation/tickets/SNI/ALPN/MFL/record-splitting (size + fidelity) */

/* ---- key exchange: the two recovered ECDSA suites ---- */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED   /* 0xC023 */
#define MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED    /* 0xC025 */

/* ---- cipher: AES-128-CBC + PKCS7 padding, SHA-256/224 MAC (no GCM/CCM/ChaCha) ---- */
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES             /* stock BE FSb/Te0/Td0/Rcon ROM tables */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_SHA256_C                   /* SHA-256 + SHA-224 (P_SHA256 PRF) */
#define MBEDTLS_MD5_C                      /* advertised sig_hash 3 (recovered {6,5,3}) */
#define MBEDTLS_MD_C
/* no SHA1_C / SHA512_C (recovered sig_hashes exclude SHA1) */

/* ---- ECC: secp256r1 ONLY, ECDH + ECDSA verify (no deterministic sign, no restart) ---- */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NO_INTERNAL_RNG      /* stock blinding RNG = caller f_rng (HW-RNG), no DRBG */
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_BIGNUM_C

/* ---- X.509 DER chain verify (CA store is DER; no PEM/base64, no CSR/CRL/write) ---- */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_REMOVE_INFO           /* drop crt_info strings (size) */

#include "mbedtls/check_config.h"
#endif /* MBEDTLS_CONFIG_H */
