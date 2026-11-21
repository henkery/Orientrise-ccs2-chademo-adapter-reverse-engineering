/* v2g_stack.h — live V2G network stack glue over the vendored lwIP 2.1.x + mbedTLS 2.28.
 * REPORT §5.9 (Agent G/H/K/L/M/N). This is the recovered transport glue wired to the REAL
 * upstream libraries (the stock C013 firmware IS lwIP + mbedTLS): lwIP owns IPv6/ND6/TCP/UDP
 * framing + reliability (raw API, NO_SYS=1), mbedTLS owns TLS 1.2 / ECDHE-ECDSA / AES-128-CBC /
 * SHA-256 / X.509, configured byte-exact via lwipopts.h + mbedtls_config.h.
 *
 * Hardware-abstracted for host unit testing: the Ethernet TX sink (eth_send) and the mbedTLS
 * RNG (f_rng) are injectable. On target eth_send = qca7005_frame_send and f_rng = hw_rng_f_rng;
 * on host a loopback netif + software RNG exercise a full client/server TLS handshake.
 *
 * Communication only — drives NO power-stage GPIO. The V2GTP deframe / EXI dispatch / transport
 * SM / TLS decision live in v2g_net.c above this layer; ca_store.c feeds the mbedTLS CA chain. */
#ifndef V2G_STACK_H
#define V2G_STACK_H
#include <stdint.h>
#include <stddef.h>
#include "ca_store.h"

#define V2G_STACK_SDP_PORT      15118u
#define V2G_STACK_UDP_SRC_PORT  0xC000u
#define V2G_STACK_RX_RING_SIZE  16384u   /* TLS bio recv ring (TCP push -> mbedTLS pull) */

typedef void (*v2g_stack_eth_send_fn)(const uint8_t *frame, uint16_t len);
typedef void (*v2g_stack_connected_fn)(void);
typedef void (*v2g_stack_app_recv_fn)(const uint8_t *data, uint16_t len); /* decrypted/plain app */
typedef void (*v2g_stack_closed_fn)(void);
typedef void (*v2g_stack_udp_recv_fn)(const uint8_t *data, uint16_t len);
typedef int  (*v2g_stack_rng_fn)(void *ctx, unsigned char *out, size_t len);

/* Bring up lwIP + the QCA7005 netif (link-local EUI-64 from mac), SDP UDP pcb. eth_send is the
 * Ethernet TX sink (netif linkoutput). Call once after qca7005_init has the PIB MAC. */
void v2g_stack_init(const uint8_t mac[6], v2g_stack_eth_send_fn eth_send);
/* Set the mbedTLS RNG (target: hw_rng_f_rng; host: software RNG). Must precede tls_setup. */
void v2g_stack_set_rng(v2g_stack_rng_fn fn, void *ctx);
/* Adapter link-local IPv6 (netif_create_ip6_linklocal_address, EUI-64). out[16] network order. */
void v2g_stack_local_ip(uint8_t out[16]);
/* RX: an Ethernet frame from the QCA7005 -> pbuf -> netif->input (ethernet_input -> ip6_input). */
void v2g_stack_rx_ethernet(const uint8_t *frame, uint16_t len);
/* Drive lwIP timeouts (tcp_tmr/nd6_tmr/ip6_reass_tmr) + deliver pending TLS app data. now_ms. */
void v2g_stack_poll(uint32_t now_ms);

/* ---- UDP SDP (multicast ff02::1:15118) ---- */
void v2g_stack_set_udp_recv(v2g_stack_udp_recv_fn fn);
int  v2g_stack_udp_send(const uint8_t *data, uint16_t len);   /* returns len or <0 */

/* ---- TCP transport (lwIP raw API pcb) ---- */
void v2g_stack_set_tcp_cbs(v2g_stack_connected_fn connected, v2g_stack_app_recv_fn recv,
                           v2g_stack_closed_fn closed);
int  v2g_stack_tcp_connect(const uint8_t secc_ip[16], uint16_t port);  /* 0 ok / <0 err */
int  v2g_stack_tcp_send(const uint8_t *data, uint16_t len);            /* plain mode; len or <0 */
void v2g_stack_tcp_close(void);
int  v2g_stack_tcp_is_connected(void);

/* ---- TLS 1.2 client (mbedTLS, recovered config) ---- */
/* Build ssl config: ciphers {0xC023,0xC025}, authmode VERIFY_REQUIRED, EtM+EMS, P_SHA256 PRF,
 * secp256r1; parse the ca_store Root certs into the CA chain; set bio (tcp_write / rx ring) + rng.
 * Returns 0 ok / <0 mbedTLS error. */
int  v2g_stack_tls_setup(const ca_store_t *ca);
/* Drive the handshake one step: 0=done, 1=WANT_READ, 2=WANT_WRITE, <0=fatal error. */
int  v2g_stack_tls_handshake(void);
int  v2g_stack_tls_write(const uint8_t *data, uint16_t len);  /* ssl_write; bytes or <0 */
int  v2g_stack_tls_read(uint8_t *out, uint16_t cap);          /* ssl_read; bytes/0/<0 */
int  v2g_stack_tls_done(void);
void v2g_stack_tls_free(void);

#endif /* V2G_STACK_H */
