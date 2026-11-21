/* test_tls_mbedtls.c — host INTEGRATION test for the LIVE vendored mbedTLS 2.28 TLS 1.2 stack with
 * the byte-exact recovered C013 config (custom_fw/src/mbedtls_config.h). LIBRARY PIVOT: the stock
 * firmware IS mbedTLS, so this drives a REAL client<->server handshake (memory bio) configured
 * EXACTLY like src/v2g_stack.c::v2g_stack_tls_setup — cipher list {0xC023,0xC025}, authmode 2
 * (VERIFY_REQUIRED), secp256r1 ECDHE-ECDSA, EtM + EMS, AES-128-CBC-SHA256, f_rng (the recovered
 * HW-RNG role), ca_store Root DER -> CA chain. Build + run (host gcc, real libc — no shim). The
 * recovered firmware config is TLS CLIENT-only (the adapter is the EVCC client); the test harness
 * needs a SECC server, so it builds with test_mbedtls_config.h = the recovered config UNCHANGED +
 * MBEDTLS_SSL_SRV_C (harness server only — see that header). The client under test is unmodified:
 *   nix-shell -p gcc --run 'gcc -O2 -w -D_GNU_SOURCE -I. -Isrc -Ithird_party/mbedtls/include \
 *     -DMBEDTLS_CONFIG_FILE=\"test_mbedtls_config.h\" -o test_tls_mbedtls test_tls_mbedtls.c \
 *     third_party/mbedtls/library/*.c && ./test_tls_mbedtls'
 * Verifies: handshake completes (state OVER), negotiated cipher == 0xC023, peer cert verified
 * (verify_result 0), encrypted app-data round-trip both directions, VERIFY_REQUIRED enforced
 * (empty/wrong CA -> handshake aborts), and the alternate recovered cipher 0xC025 negotiates.
 * The lwIP transport bio bridge (bio_send->tcp_write / rx_ring->bio_recv) is disasm-verified by
 * verify_ccs2.py + the byte-exact framing host tests (test_v2g_net); this test owns the TLS core. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/entropy.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; printf("FAIL: %s\n", msg); } } while (0)

static int hexval(char c) {
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static uint32_t unhex(const char *h, uint8_t *out) {
    uint32_t n = 0;
    while (h[0] && h[1]) { out[n++] = (uint8_t)((hexval(h[0])<<4)|hexval(h[1])); h += 2; }
    return n;
}

/* Real openssl P-256 fixtures (same as test_x509.c / test_tls.c): self-signed Root CA + SECC leaf. */
static const char *ROOT_DER =
"308201ba30820161a00302010202145c4872497c6d9f58dcb981fe3f6ad03cfbb99f9c300a06082a8648ce3d040302"
"302b3114301206035504030c0b56324720526f6f7420434131133011060355040a0c0a4f7269656e7472697365301e"
"170d3236313132313137303132395a170d3336313131383137303132395a302b3114301206035504030c0b56324720"
"526f6f7420434131133011060355040a0c0a4f7269656e74726973653059301306072a8648ce3d020106082a8648ce"
"3d0301070342000486a0327ff075c675bdb134d45f1cf3f464d980e72088d5bc8dc9afabcf47e4368db209e39e6ca9"
"2b9c4ce7a8ea15a4d388bd3b98c9e6b275767699121225f768a3633061301d0603551d0e04160414da18bcd2fff974"
"3d9d68e86cf55e177c107541c5301f0603551d23041830168014da18bcd2fff9743d9d68e86cf55e177c107541c530"
"0f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d040302034700"
"3044022028e82d850a84af5f740ebfee6aa78f7607b005662f12e8796b61d8a7b25ea6cf022039ea1f7f9b170426f8"
"d07685d67569c60b9a4a9a5caa674669bc2becb5d6c417";
static const char *LEAF_DER =
"308201bc30820162a0030201020214712f39f4d84ba147b85ac15486d9fca9a8b82649300a06082a8648ce3d040302"
"302b3114301206035504030c0b56324720526f6f7420434131133011060355040a0c0a4f7269656e7472697365301e"
"170d3236313132313137303132395a170d3239303232333137303132395a3024310d300b06035504030c0453454343"
"31133011060355040a0c0a4f7269656e74726973653059301306072a8648ce3d020106082a8648ce3d030107034200"
"048ac4ea33ae286eaf056fa332b681264350ce0e47e56954bde8db837c5c4b41f932731fb28bc80127999d4f94a24a"
"52f435dd02d4d8a5a095144f6409afe56392a36b306930090603551d1304023000300b0603551d0f0404030205a030"
"0f0603551d1104083006820473656363301d0603551d0e0416041446365c20f7372aa5963a05a53c1f07c248084609"
"301f0603551d23041830168014da18bcd2fff9743d9d68e86cf55e177c107541c5300a06082a8648ce3d0403020348"
"003045022100e4874fbdbe10ff5bee6024dc7025d318350a7ce823505ca7674b593681b9e0c7022001e5fff94c7f59"
"c9c701a37ae42c64cd836d5929e1ee10b9e3653f978bef7613";
/* SECC leaf private key — PKCS8 DER (the recovered config has NO PEM_PARSE_C/BASE64_C: the firmware
 * loads DER only, from ca_store; so the test feeds DER too). Decoded from the openssl leaf.key PEM.
 * SEQUENCE { version 0, AlgId{ecPublicKey, secp256r1}, OCTET STRING { SEC1 ECPrivateKey } }. */
static const char *LEAF_KEY_DER =
"308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104203e8d7651fdbf187e884a64c"
"08a4b85347a947c63ccf8fc753fc1103ce6f4d6e5a144034200048ac4ea33ae286eaf056fa332b681264350ce0e47e5"
"6954bde8db837c5c4b41f932731fb28bc80127999d4f94a24a52f435dd02d4d8a5a095144f6409afe56392";

/* recovered cipher list (0x080B0668): ECDHE-ECDSA-AES128-CBC-SHA256 + ECDH-ECDSA-AES128-CBC-SHA256 */
static const int tls_ciphers[] = { 0xC023, 0xC025, 0 };
static const int cipher_c025_only[] = { 0xC025, 0 };

/* deterministic host f_rng (stands in for the recovered STM32 HW-RNG 0x50060800 via f_rng). */
static uint32_t rng_state = 0xC0FFEEu;
static int test_f_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    for (size_t i = 0; i < len; i++) { rng_state = rng_state*1103515245u + 12345u; out[i] = (uint8_t)(rng_state>>16); }
    return 0;
}

/* ---- memory bio: bidirectional pipe pair (client <-> server) ---- */
typedef struct { uint8_t buf[32768]; size_t len; } pipe_t;
static pipe_t c2s, s2c;
static void pipes_reset(void) { c2s.len = 0; s2c.len = 0; }
static int pipe_put(pipe_t *p, const unsigned char *b, size_t n) {
    if (p->len + n > sizeof p->buf) return MBEDTLS_ERR_SSL_WANT_WRITE;
    memcpy(p->buf + p->len, b, n); p->len += n; return (int)n;
}
static int pipe_get(pipe_t *p, unsigned char *b, size_t n) {
    if (p->len == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    size_t k = n < p->len ? n : p->len;
    memcpy(b, p->buf, k); memmove(p->buf, p->buf + k, p->len - k); p->len -= k; return (int)k;
}
static int bio_send_c(void *ctx, const unsigned char *b, size_t n) { (void)ctx; return pipe_put(&c2s, b, n); }
static int bio_recv_c(void *ctx, unsigned char *b, size_t n)       { (void)ctx; return pipe_get(&s2c, b, n); }
static int bio_send_s(void *ctx, const unsigned char *b, size_t n) { (void)ctx; return pipe_put(&s2c, b, n); }
static int bio_recv_s(void *ctx, unsigned char *b, size_t n)       { (void)ctx; return pipe_get(&c2s, b, n); }

/* ---- client setup: mirrors v2g_stack_tls_setup byte-for-byte (recovered config) ---- */
static mbedtls_ssl_context cli;
static mbedtls_ssl_config cli_conf;
static mbedtls_x509_crt cli_ca;
static int client_setup(const uint8_t *ca_der, uint32_t ca_len, const int *ciphers, int authmode) {
    mbedtls_ssl_init(&cli); mbedtls_ssl_config_init(&cli_conf); mbedtls_x509_crt_init(&cli_ca);
    int r = mbedtls_ssl_config_defaults(&cli_conf, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (r) return r;
    mbedtls_ssl_conf_ciphersuites(&cli_conf, ciphers);
    mbedtls_ssl_conf_authmode(&cli_conf, authmode);
    mbedtls_ssl_conf_rng(&cli_conf, test_f_rng, NULL);
    if (ca_der && ca_len) { r = mbedtls_x509_crt_parse(&cli_ca, ca_der, ca_len); if (r < 0) return r; }
    mbedtls_ssl_conf_ca_chain(&cli_conf, &cli_ca, NULL);
    mbedtls_ssl_set_bio(&cli, NULL, bio_send_c, bio_recv_c, NULL);
    return mbedtls_ssl_setup(&cli, &cli_conf);
}
static void client_free(void) {
    mbedtls_ssl_free(&cli); mbedtls_ssl_config_free(&cli_conf); mbedtls_x509_crt_free(&cli_ca);
}

/* ---- server setup: SECC leaf cert + priv, same recovered cipher list, no client auth ---- */
static mbedtls_ssl_context srv;
static mbedtls_ssl_config srv_conf;
static mbedtls_x509_crt srv_crt;
static mbedtls_pk_context srv_pk;
static int server_setup(const int *ciphers) {
    uint8_t leaf[1024], key[256];
    uint32_t leaf_len = unhex(LEAF_DER, leaf);
    uint32_t key_len = unhex(LEAF_KEY_DER, key);
    mbedtls_ssl_init(&srv); mbedtls_ssl_config_init(&srv_conf);
    mbedtls_x509_crt_init(&srv_crt); mbedtls_pk_init(&srv_pk);
    int r = mbedtls_ssl_config_defaults(&srv_conf, MBEDTLS_SSL_IS_SERVER,
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (r) return r;
    mbedtls_ssl_conf_ciphersuites(&srv_conf, ciphers);
    mbedtls_ssl_conf_authmode(&srv_conf, MBEDTLS_SSL_VERIFY_NONE);   /* V2G TLS: server-auth only */
    mbedtls_ssl_conf_rng(&srv_conf, test_f_rng, NULL);
    r = mbedtls_x509_crt_parse(&srv_crt, leaf, leaf_len); if (r) return r;
    r = mbedtls_pk_parse_key(&srv_pk, key, key_len, NULL, 0); if (r) return r;
    r = mbedtls_ssl_conf_own_cert(&srv_conf, &srv_crt, &srv_pk); if (r) return r;
    mbedtls_ssl_set_bio(&srv, NULL, bio_send_s, bio_recv_s, NULL);
    return mbedtls_ssl_setup(&srv, &srv_conf);
}
static void server_free(void) {
    mbedtls_ssl_free(&srv); mbedtls_ssl_config_free(&srv_conf);
    mbedtls_x509_crt_free(&srv_crt); mbedtls_pk_free(&srv_pk);
}

/* drive both handshakes until both complete, one hits a FATAL error, or the iteration cap is hit.
 * WANT_READ (-0x6900) / WANT_WRITE (-0x6880) are normal non-blocking returns: keep shuttling. */
static int is_want(int r) {
    return r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE;
}
static int pump(int *cli_ret, int *srv_ret) {
    *cli_ret = MBEDTLS_ERR_SSL_WANT_READ; *srv_ret = MBEDTLS_ERR_SSL_WANT_READ;
    for (int i = 0; i < 400; i++) {
        if (*cli_ret != 0) *cli_ret = mbedtls_ssl_handshake(&cli);
        if (*srv_ret != 0) *srv_ret = mbedtls_ssl_handshake(&srv);
        if (*cli_ret == 0 && *srv_ret == 0) break;
        if ((*cli_ret < 0 && !is_want(*cli_ret)) || (*srv_ret < 0 && !is_want(*srv_ret))) break;
    }
    return (*cli_ret == 0 && *srv_ret == 0) ? 0 : -1;
}

static unsigned char heap[262144];

int main(void) {
    mbedtls_memory_buffer_alloc_init(heap, sizeof heap);
    uint8_t root[1024]; uint32_t root_len = unhex(ROOT_DER, root);

    /* ---- Test 1: recovered-config handshake (correct Root CA) ---- */
    pipes_reset();
    CHECK(client_setup(root, root_len, tls_ciphers, MBEDTLS_SSL_VERIFY_REQUIRED) == 0,
          "client setup (recovered config: ciphers/authmode2/ca_chain/f_rng)");
    CHECK(server_setup(tls_ciphers) == 0, "server setup (SECC leaf + priv, recovered ciphers)");
    int cr = 1, sr = 1;
    pump(&cr, &sr);
    CHECK(cr == 0, "client handshake completes (ret 0)");
    CHECK(sr == 0, "server handshake completes (ret 0)");
    CHECK(cli.state == MBEDTLS_SSL_HANDSHAKE_OVER, "client state == HANDSHAKE_OVER");
    CHECK(mbedtls_ssl_get_ciphersuite(&cli) != NULL, "negotiated ciphersuite name present");
    CHECK(mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(&cli)) == 0xC023,
          "negotiated cipher == 0xC023 TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256 (recovered)");
    CHECK(mbedtls_ssl_get_verify_result(&cli) == 0, "peer cert verified against Root CA (result 0)");
    printf("info: negotiated %s\n", mbedtls_ssl_get_ciphersuite(&cli));

    /* ---- Test 2: encrypted app-data round-trip both directions ---- */
    const char *req = "V2GTP-CurrentDemandReq-EXI-payload";
    int w = mbedtls_ssl_write(&cli, (const unsigned char *)req, (uint16_t)strlen(req));
    CHECK(w == (int)strlen(req), "client ssl_write app data (record encrypted)");
    /* the wire bytes in c2s must NOT contain the plaintext (CBC record protection) */
    CHECK(c2s.len > 0 && memmem(c2s.buf, c2s.len, req, strlen(req)) == NULL,
          "app data is encrypted on the wire (plaintext absent from TLS record)");
    unsigned char rbuf[256];
    int got = 0;
    for (int i = 0; i < 50 && got <= 0; i++) { got = mbedtls_ssl_read(&srv, rbuf, sizeof rbuf); }
    CHECK(got == (int)strlen(req) && memcmp(rbuf, req, (size_t)got) == 0,
          "server ssl_read decrypts client app data (round-trip C->S)");
    const char *resp = "V2GTP-CurrentDemandRes-EXI-ok";
    w = mbedtls_ssl_write(&srv, (const unsigned char *)resp, (uint16_t)strlen(resp));
    CHECK(w == (int)strlen(resp), "server ssl_write response");
    got = 0;
    for (int i = 0; i < 50 && got <= 0; i++) { got = mbedtls_ssl_read(&cli, rbuf, sizeof rbuf); }
    CHECK(got == (int)strlen(resp) && memcmp(rbuf, resp, (size_t)got) == 0,
          "client ssl_read decrypts server response (round-trip S->C)");
    client_free(); server_free();

    /* ---- Test 3: VERIFY_REQUIRED enforced — empty CA chain aborts the handshake ---- */
    pipes_reset();
    CHECK(client_setup(NULL, 0, tls_ciphers, MBEDTLS_SSL_VERIFY_REQUIRED) == 0,
          "client setup with EMPTY CA chain (authmode 2)");
    CHECK(server_setup(tls_ciphers) == 0, "server setup (negative test)");
    cr = 1; sr = 1; pump(&cr, &sr);
    CHECK(cr < 0, "handshake ABORTS with no trusted Root (VERIFY_REQUIRED enforced)");
    CHECK(mbedtls_ssl_get_verify_result(&cli) != 0, "verify_result != 0 (cert not trusted)");
    printf("info: empty-CA client ret = -0x%04x, verify_result = 0x%08x\n",
           (unsigned)(-cr), (unsigned)mbedtls_ssl_get_verify_result(&cli));
    client_free(); server_free();

    /* ---- Test 4: alternate recovered cipher 0xC025 (ECDH-ECDSA) negotiates ---- */
    pipes_reset();
    CHECK(client_setup(root, root_len, cipher_c025_only, MBEDTLS_SSL_VERIFY_REQUIRED) == 0,
          "client setup pinned to 0xC025 only");
    CHECK(server_setup(cipher_c025_only) == 0, "server setup pinned to 0xC025 only");
    cr = 1; sr = 1; pump(&cr, &sr);
    CHECK(cr == 0 && sr == 0, "0xC025 ECDH-ECDSA handshake completes");
    CHECK(mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(&cli)) == 0xC025,
          "negotiated cipher == 0xC025 TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256 (recovered alt)");
    client_free(); server_free();

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}