/* ca_store.h — ISO 15118 PnC certificate store populator (REPORT §5.9, Agent N).
 *
 * Faithful INERT replica of the C013 CA cert-store refresh/populator glue that loads the Root-CA
 * chain into the mbedTLS config (authmode 2 VERIFY_REQUIRED) and whose Root-cert count gates the
 * SDP TLS decision (sdp_security_select: count low-byte==0 -> No-TLS). Byte-derived from:
 *
 *   two stores      external SPI flash (master) header @0x1F8000 / data @0x1F8010, read via SPI4
 *                   READ 0x08088CFE (cmd 0x03 + 24-bit addr; == custom_fw spi4_read); internal
 *                   flash A/B copies 0x0800C000 (sector3) / 0x08010000 (sector4), memory-mapped.
 *   ext header      16 B @0x1F8000: [0] magic 0xCEA155E1, [4] version=1, [8] data size,
 *                   [12] byte-sum checksum. Refresh validation 0x0805184C: magic==0xCEA155E1
 *                   (@0x08051862), version==1 (@0x0805186C), size>=808 (@0x08051872 cmp #0x328),
 *                   size 4-aligned (lsls #0x1e), byte-sum over data == hdr[12] (@0x080518F8).
 *   entry           808 B (0x328) {+0 msg_code u32, +4 der_len u32 (<=800=0x320; Contract=0x20),
 *                   +8 DER[der_len]}. Validator 0x08051CE2: msg_code==expected && 0<der_len<=0x320
 *                   (ret 0 valid / -1 invalid); Contract validator 0x08051CFE: der_len==0x20.
 *   slot map        Root 0x8101 slots0-4 (808 B each), Pri_root 0x8102, Oem 0x8105, 0x8104, 0x8103,
 *                   Contract 0x8109 (compact 40 B), 0x8108/0x8107/0x8106 (Contract group), 0x8109
 *                   2nd. Internal offsets 0x8/0x330/0x658/0x980/0xCA8/0xFD0/0x12F8/...; the ext
 *                   data image is the packed entry sequence (ext offset = internal offset - 8).
 *   internal hdr    [0] magic 0xCEA155E1, [4] version=0, [0x2638] sequence (non-zero),
 *                   [0x263C] tail 0xCEA2AAE1. Validator 0x08051500; base getter 0x0805159C picks
 *                   the higher-sequence A/B copy; A/B commit 0x08051526 (alternate sector, seq+1).
 *   populate        0x080515CC: config 0x20018A44 memset 0x28; config[0]=store base; root loop
 *                   slot0-4 validate(entry,0x8101) -> 0x08051680 r0=entry+4 ({der_len,DER}),
 *                   0x08051684 stm r6!,{r0} append to the compact NULL-terminated root-cert-ptr
 *                   array @config+4=0x20018A48; count -> config[0x20]=0x20018A64 (SDP TLS gate).
 *   CA-chain load   getter 0x08051ADC (0x20018A6C-0x24 -> 0x20018A48 ptr array); caller 0x080208CA
 *                   bl getter; movs r1,#0 (arg1=0); bl mbedtls setup 0x080604D2: loop <=5 ldm
 *                   ptr (NULL->done), ldm der_len + DER ptr, x509_crt_parse 0x0805D76C, then
 *                   ssl_conf_ca_chain 0x0808FAD6 + authmode (arg1==0 -> 2 VERIFY_REQUIRED @0x08060568,
 *                   else 1 VERIFY_OPTIONAL) ssl_conf_authmode 0x0808F442.
 *
 * INERT: communication only — drives NO power-stage GPIO. The stock copies ext-SPI -> internal-flash
 * A/B (memory-mapped) -> RAM pointer array; the bare-metal replica reads the ext-SPI master directly
 * into RAM (it does not manage internal A/B sectors 3/4) and builds the same compact NULL-terminated
 * root-cert pointer list + count. The DER bytes are exposed for the mbedTLS CA chain; the X509
 * parse/verify internals are the gated crypto layer (Agent M / tls.c). Pure validation + populate
 * logic is host-unit-tested (test_ca_store.c) via an injected read hook (NULL = spi4_read).
 */
#ifndef CA_STORE_H
#define CA_STORE_H
#include <stdint.h>

#define CA_EXT_HDR_ADDR    0x1F8000u   /* external SPI flash header                */
#define CA_EXT_DATA_ADDR   0x1F8010u   /* external SPI flash cert data start       */
#define CA_MAGIC           0xCEA155E1u /* header[0] / internal[0]                  */
#define CA_TAIL_MAGIC      0xCEA2AAE1u /* internal[0x263C]                         */
#define CA_EXT_VERSION     1u          /* ext header[4] (internal version is 0)    */
#define CA_ENTRY_SIZE      808u        /* 0x328 = 8 hdr + 800 DER                  */
#define CA_DER_MAX         800u        /* 0x320 max DER length                     */
#define CA_CONTRACT_DER    32u         /* 0x20 Contract cert DER length            */
#define CA_ROOT_SLOTS      5u          /* Root 0x8101 slots 0-4                    */
#define CA_DATA_MAX        9792u       /* 0x2640 full internal image bound         */

/* V2G PnC message codes (msg_code field of each entry) */
#define CA_MSG_ROOT        0x8101u
#define CA_MSG_PRI_ROOT    0x8102u
#define CA_MSG_OEM         0x8105u
#define CA_MSG_CONTRACT    0x8109u

/* RAM image of one 808-byte entry: msg_code@0, der_len@4, der@8 (entry+4 = {der_len,DER}). */
typedef struct {
    uint32_t msg_code;
    uint32_t der_len;
    uint8_t  der[CA_DER_MAX];
} ca_entry_t;

typedef struct {
    uint8_t  hdr_valid;        /* ext header magic/version/size/alignment OK        */
    uint8_t  cksum_ok;         /* data byte-sum == hdr[12]                          */
    uint8_t  store_present;    /* hdr_valid && cksum_ok                             */
    uint32_t ext_version;      /* hdr[4]                                            */
    uint32_t ext_size;         /* hdr[8]                                            */
    uint32_t ext_cksum;        /* hdr[12] stored                                    */
    uint32_t calc_cksum;       /* computed byte-sum over data                       */
    uint8_t  root_count;       /* valid Root certs (compact; gates SDP TLS)         */
    ca_entry_t root[CA_ROOT_SLOTS];          /* compacted valid Root entries        */
    const uint8_t *root_ptr[CA_ROOT_SLOTS + 1]; /* NULL-term ptrs to &root[i].der_len */
    ca_entry_t pri_root; uint8_t pri_root_valid;  /* 0x8102 @ ext 0xFC8             */
    ca_entry_t oem;      uint8_t oem_valid;       /* 0x8105 @ ext 0x12F0            */
    ca_entry_t contract; uint8_t contract_valid;  /* 0x8109 @ ext 0x1C68 (40 B)     */
} ca_store_t;

/* Read hook: read `len` bytes from external flash offset `addr` (NULL = spi4_read). Returns 0 ok. */
typedef int (*ca_read_fn)(uint32_t addr, uint8_t *dst, uint32_t len);
void ca_store_set_read(ca_read_fn fn);
/* Read + validate the ext header, checksum the data, populate the root-cert ptr array + count. */
void ca_store_init(void);
const ca_store_t *ca_store_get(void);
/* Root-cert count (the SDP TLS gate: sdp_security_select(count)). */
uint8_t ca_store_root_count(void);

/* ---- pure, host-testable helpers (byte-exact, no hardware) ---- */
/* 0x0805184C: validate a 16-byte ext header (magic==0xCEA155E1, version==1, size>=808, size%4==0). */
int ca_hdr_valid(const uint8_t *hdr);
/* Byte-sum checksum over data[0..len) (the ext header[12] algorithm). */
uint32_t ca_byte_sum(const uint8_t *data, uint32_t len);
/* 0x08051CE2: entry msg_code==expected && 0<der_len<=800. Returns 1 valid / 0 invalid. */
int ca_entry_valid(const uint8_t *entry, uint32_t msg_code);
/* 0x08051CFE: Contract entry msg_code==expected && der_len==32. Returns 1 valid / 0 invalid. */
int ca_contract_valid(const uint8_t *entry, uint32_t msg_code);
/* 0x080515CC: populate the compact root-cert ptr array from a data image (Root slots 0-4 at
 * 808*i). Copies valid entries into st->root[], sets root_ptr[] (NULL-term) + root_count. Returns
 * the valid-root count. Also reads/validates Pri_root/Oem/Contract at their packed offsets. */
uint8_t ca_populate(ca_store_t *st, const uint8_t *data, uint32_t size);

#endif /* CA_STORE_H */