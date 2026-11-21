/* ca_store.c — ISO 15118 PnC certificate store populator (REPORT §5.9, Agent N).
 * Faithful INERT replica of the C013 CA refresh/populator glue. Pure validation + populate logic
 * host-tested (test_ca_store.c) via an injected read hook (NULL = spi4_read). No power GPIO.
 * The stock ext-SPI -> internal-A/B (memory-mapped) -> RAM ptr-array becomes ext-SPI -> RAM here
 * (the bare-metal app does not manage internal A/B sectors 3/4). X509 parse is the gated crypto layer.
 */
#include "ca_store.h"
#include "spi4.h"

static ca_store_t store;
static ca_read_fn read_hook;
static uint8_t hdr[16];
static uint8_t data_buf[CA_DATA_MAX];

static void z(uint8_t *p, uint32_t n) { for (uint32_t i = 0; i < n; i++) p[i] = 0; }
static void cp(uint8_t *d, const uint8_t *s, uint32_t n) { for (uint32_t i = 0; i < n; i++) d[i] = s[i]; }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

void ca_store_set_read(ca_read_fn fn) { read_hook = fn; }

int ca_hdr_valid(const uint8_t *h)
{
    /* 0x0805184C: magic @0x08051862, version==1 @0x0805186C, size>=808 @0x08051872, 4-aligned. */
    if (le32(h) != CA_MAGIC) return 0;
    if (le32(h + 4) != CA_EXT_VERSION) return 0;
    uint32_t size = le32(h + 8);
    if (size < CA_ENTRY_SIZE) return 0;
    if (size & 3u) return 0;
    return 1;
}

uint32_t ca_byte_sum(const uint8_t *data, uint32_t len)
{
    uint32_t sum = 0;
    for (uint32_t i = 0; i < len; i++) sum += data[i];
    return sum;
}

int ca_entry_valid(const uint8_t *entry, uint32_t msg_code)
{
    /* 0x08051CE2: msg_code==expected && 0<der_len<=0x320. */
    if (le32(entry) != msg_code) return 0;
    uint32_t der_len = le32(entry + 4);
    return (der_len > 0u && der_len <= CA_DER_MAX) ? 1 : 0;
}

int ca_contract_valid(const uint8_t *entry, uint32_t msg_code)
{
    /* 0x08051CFE: msg_code==expected && der_len==0x20. */
    if (le32(entry) != msg_code) return 0;
    return (le32(entry + 4) == CA_CONTRACT_DER) ? 1 : 0;
}

uint8_t ca_populate(ca_store_t *st, const uint8_t *data, uint32_t size)
{
    /* 0x080515CC root loop: validate slot0-4 (0x8101), append entry+4 ({der_len,DER}) to the compact
     * NULL-terminated ptr array, count valid roots. Ext data is the packed entry sequence. */
    z((uint8_t *)st->root, sizeof st->root);
    z((uint8_t *)st->root_ptr, sizeof st->root_ptr);
    st->root_count = 0;
    st->pri_root_valid = 0; st->oem_valid = 0; st->contract_valid = 0;

    uint8_t count = 0;
    for (uint8_t i = 0; i < CA_ROOT_SLOTS; i++) {
        uint32_t off = (uint32_t)i * CA_ENTRY_SIZE;
        if (off + CA_ENTRY_SIZE > size) break;
        const uint8_t *entry = data + off;
        if (ca_entry_valid(entry, CA_MSG_ROOT)) {
            cp((uint8_t *)&st->root[count], entry, CA_ENTRY_SIZE);
            st->root_ptr[count] = (const uint8_t *)&st->root[count].der_len;   /* entry+4 */
            count++;
        }
    }
    st->root_ptr[count] = 0;   /* NULL-terminate */
    st->root_count = count;

    /* Pri_root 0x8102 @ ext 0xFC8 (808*5), Oem 0x8105 @ ext 0x12F0 (808*6). */
    uint32_t off = CA_ROOT_SLOTS * CA_ENTRY_SIZE;   /* 0xFC8 */
    if (off + CA_ENTRY_SIZE <= size && ca_entry_valid(data + off, CA_MSG_PRI_ROOT)) {
        cp((uint8_t *)&st->pri_root, data + off, CA_ENTRY_SIZE);
        st->pri_root_valid = 1;
    }
    off += CA_ENTRY_SIZE;   /* 0x12F0 */
    if (off + CA_ENTRY_SIZE <= size && ca_entry_valid(data + off, CA_MSG_OEM)) {
        cp((uint8_t *)&st->oem, data + off, CA_ENTRY_SIZE);
        st->oem_valid = 1;
    }
    /* Contract 0x8109 @ ext 0x1C68 (808*9), compact 40 B (8 hdr + 32 DER). */
    off = 9u * CA_ENTRY_SIZE;   /* 0x1C68 */
    if (off + 40u <= size && ca_contract_valid(data + off, CA_MSG_CONTRACT)) {
        cp((uint8_t *)&st->contract, data + off, 40u);
        st->contract_valid = 1;
    }
    return count;
}

void ca_store_init(void)
{
    z((uint8_t *)&store, sizeof store);
    ca_read_fn rd = read_hook ? read_hook : spi4_read;

    if (rd(CA_EXT_HDR_ADDR, hdr, 16u) != 0) return;
    store.ext_version = le32(hdr + 4);
    store.ext_size = le32(hdr + 8);
    store.ext_cksum = le32(hdr + 12);
    store.hdr_valid = (uint8_t)ca_hdr_valid(hdr);
    if (!store.hdr_valid) return;

    uint32_t n = store.ext_size;
    if (n > CA_DATA_MAX) n = CA_DATA_MAX;
    if (rd(CA_EXT_DATA_ADDR, data_buf, n) != 0) return;
    store.calc_cksum = ca_byte_sum(data_buf, n);
    store.cksum_ok = (uint8_t)(store.calc_cksum == store.ext_cksum);
    store.store_present = (uint8_t)(store.hdr_valid && store.cksum_ok);
    if (store.store_present) ca_populate(&store, data_buf, n);
}

const ca_store_t *ca_store_get(void) { return &store; }
uint8_t ca_store_root_count(void) { return store.root_count; }