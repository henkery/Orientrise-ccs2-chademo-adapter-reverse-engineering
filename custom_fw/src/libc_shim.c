/* libc_shim.c — freestanding mem and str functions + errno + lwIP port for the vendored
 * libraries. Compiled with -fno-builtin -fno-tree-loop-distribute-patterns so gcc does not
 * turn these loops back into calls to themselves. No libc heap: mbedTLS MEMORY_BUFFER_ALLOC. */
#include "libc_shim.h"
#include <stdint.h>

int errno;

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst; const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst; const uint8_t *s = (const uint8_t *)src;
    if (d == s || n == 0) return dst;
    if (d < s) { for (size_t i = 0; i < n; i++) d[i] = s[i]; }
    else { for (size_t i = n; i > 0; i--) d[i - 1] = s[i - 1]; }
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    uint8_t *d = (uint8_t *)dst; uint8_t v = (uint8_t)c;
    for (size_t i = 0; i < n; i++) d[i] = v;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++) if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    return 0;
}

void *memchr(const void *s, int c, size_t n)
{
    const uint8_t *p = (const uint8_t *)s; uint8_t v = (uint8_t)c;
    for (size_t i = 0; i < n; i++) if (p[i] == v) return (void *)(p + i);
    return 0;
}

size_t strlen(const char *s)
{
    size_t n = 0; while (s[n]) n++; return n;
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(uint8_t)*a - (int)(uint8_t)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)(uint8_t)a[i] - (int)(uint8_t)b[i];
        if (!a[i]) return 0;
    }
    return 0;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    size_t i = 0;
    for (; i < n && src[i]; i++) dst[i] = src[i];
    for (; i < n; i++) dst[i] = 0;
    return dst;
}

char *strchr(const char *s, int c)
{
    char v = (char)c;
    for (; *s; s++) if (*s == v) return (char *)s;
    return v ? 0 : (char *)s;
}

char *strstr(const char *hay, const char *needle)
{
    if (!*needle) return (char *)hay;
    for (; *hay; hay++) {
        const char *h = hay, *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return (char *)hay;
    }
    return 0;
}

/* lwIP LWIP_RAND: IPv6 flow-label / ND6 nonce. LCG (TCP ISS uses tcp_ticks, not this). */
static unsigned int rand_state = 0x12345678u;
unsigned int lwip_rand_shim(void)
{
    rand_state = rand_state * 1103515245u + 12345u;
    return rand_state;
}

/* lwIP NO_SYS=1 port: monotonic millisecond clock. The app tick (SysTick / 100 Hz loop)
 * advances lwip_now_ms; lwIP timeouts (tcp_tmr, nd6_tmr, ip6_reass_tmr) read it via sys_now. */
volatile uint32_t lwip_now_ms;
uint32_t sys_now(void) { return lwip_now_ms; }

/* Linkage stubs for the mbedTLS platform static initializers (mbedtls_calloc_func=calloc,
 * mbedtls_free_func=free) and mbedtls_exit. mbedtls_memory_buffer_alloc_init() overrides the
 * calloc/free pointers with the library buffer allocator BEFORE any allocation, so these are
 * never reached; exit is only invoked on a fatal heap-corruption check. Trap if ever called. */
void *calloc(size_t n, size_t s) { (void)n; (void)s; for (;;) {} }
void free(void *p) { (void)p; for (;;) {} }
void exit(int code) { (void)code; for (;;) {} }
