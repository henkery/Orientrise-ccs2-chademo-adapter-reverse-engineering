/* libc_shim.h — tiny freestanding libc subset for the vendored mbedTLS + lwIP build.
 * The app links -nostdlib; the libraries call the mem and str functions + errno. mbedTLS
 * heap is provided by MBEDTLS_MEMORY_BUFFER_ALLOC_C (static pool), so no calloc/free shim. */
#ifndef LIBC_SHIM_H
#define LIBC_SHIM_H
#include <stddef.h>
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
void *memchr(const void *s, int c, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strncpy(char *dst, const char *src, size_t n);
char *strchr(const char *s, int c);
char *strstr(const char *hay, const char *needle);
unsigned int lwip_rand_shim(void);
#endif /* LIBC_SHIM_H */
