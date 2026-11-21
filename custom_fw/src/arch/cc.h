/* arch/cc.h — lwIP compiler/arch abstraction for freestanding ARM Cortex-M4 (gcc).
 * Little-endian, packed structs, no libc inttypes/ctype; diag/assert compiled out
 * (LWIP_DEBUG=0, LWIP_NOASSERT=1). LWIP_RAND backs IPv6 flow-label / ND6 nonce from the
 * libc-shim LCG (the stock TCP ISS uses tcp_ticks, not RNG). */
#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321
#define BYTE_ORDER    LITTLE_ENDIAN

#define LWIP_NO_STDINT_H   0
#define LWIP_NO_STDDEF_H   0
#define LWIP_NO_LIMITS_H   0
#define LWIP_NO_INTTYPES_H 1
#define LWIP_NO_CTYPE_H    1

#define LWIP_CONST_CAST(target_type, val) ((target_type)(val))
#define LWIP_ALIGNMENT_CAST(target_type, val) LWIP_CONST_CAST(target_type, val)
#define LWIP_PTR_NUMERIC_CAST(target_type, val) LWIP_CONST_CAST(target_type, val)

#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(x) x

#define LWIP_PLATFORM_DIAG(x)   do {} while (0)
#define LWIP_PLATFORM_ASSERT(x) do {} while (0)

unsigned int lwip_rand_shim(void);
#define LWIP_RAND() (lwip_rand_shim())

#endif /* LWIP_ARCH_CC_H */
