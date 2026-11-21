/* test_ca_store.c — host unit test for the PnC CA cert-store populator (custom_fw/src/ca_store.c,
 * REPORT §5.9, Agent N). Build + run:
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_ca_store \
 *       test_ca_store.c src/ca_store.c && ./test_ca_store'
 * spi4_read is stubbed (the test injects a RAM-backed read hook). */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ca_store.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

/* linker stub: ca_store.c references spi4_read as the default hook (never called when injected). */
int spi4_read(uint32_t addr, uint8_t *dst, uint32_t len) { (void)addr; (void)dst; (void)len; return -1; }

static void put32(uint8_t *p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }

/* write one 808-byte entry: msg_code@0, der_len@4, DER@8 filled with `fill`. */
static void mk_entry(uint8_t *e, uint32_t msg_code, uint32_t der_len, uint8_t fill)
{
    memset(e, 0, CA_ENTRY_SIZE);
    put32(e, msg_code); put32(e + 4, der_len);
    for (uint32_t i = 0; i < der_len && i < CA_DER_MAX; i++) e[8 + i] = fill;
}

/* RAM-backed external flash image: hdr[16] @0x1F8000, data @0x1F8010. */
static uint8_t img[16 + CA_DATA_MAX];
static uint32_t img_size;
static int fake_read(uint32_t addr, uint8_t *dst, uint32_t len)
{
    uint32_t off = addr - CA_EXT_HDR_ADDR;
    if (off + len > 16 + img_size) return -1;
    memcpy(dst, img + off, len);
    return 0;
}
static void build_hdr(uint32_t version, uint32_t size, uint32_t cksum)
{
    put32(img + 0, CA_MAGIC); put32(img + 4, version); put32(img + 8, size); put32(img + 12, cksum);
}
static uint32_t data_sum(uint32_t size) { uint32_t s = 0; for (uint32_t i = 0; i < size; i++) s += img[16 + i]; return s; }

int main(void)
{
    /* --- ca_hdr_valid (0x0805184C): magic/version==1/size>=808/4-aligned --- */
    uint8_t h[16];
    put32(h, CA_MAGIC); put32(h+4, 1); put32(h+8, 808); put32(h+12, 0);
    CHECK(ca_hdr_valid(h)==1, "valid ext header");
    put32(h, 0xDEADBEEF); CHECK(ca_hdr_valid(h)==0, "reject bad magic"); put32(h, CA_MAGIC);
    put32(h+4, 0); CHECK(ca_hdr_valid(h)==0, "reject version 0 (internal, not ext)"); put32(h+4, 1);
    put32(h+8, 807); CHECK(ca_hdr_valid(h)==0, "reject size<808"); put32(h+8, 808);
    put32(h+8, 809); CHECK(ca_hdr_valid(h)==0, "reject size not 4-aligned"); put32(h+8, 812);
    CHECK(ca_hdr_valid(h)==1, "accept size 812 (4-aligned, >=808)");

    /* --- ca_byte_sum --- */
    uint8_t bs[4] = {1, 2, 3, 4};
    CHECK(ca_byte_sum(bs, 4)==10, "byte sum 1+2+3+4=10");
    CHECK(ca_byte_sum(bs, 0)==0, "byte sum empty 0");

    /* --- ca_entry_valid (0x08051CE2): msg_code match + 0<der_len<=800 --- */
    uint8_t e[CA_ENTRY_SIZE];
    mk_entry(e, CA_MSG_ROOT, 100, 0xA5);
    CHECK(ca_entry_valid(e, CA_MSG_ROOT)==1, "valid root entry");
    CHECK(ca_entry_valid(e, CA_MSG_OEM)==0, "reject wrong msg_code");
    mk_entry(e, CA_MSG_ROOT, 0, 0); CHECK(ca_entry_valid(e, CA_MSG_ROOT)==0, "reject der_len 0");
    mk_entry(e, CA_MSG_ROOT, 800, 0); CHECK(ca_entry_valid(e, CA_MSG_ROOT)==1, "accept der_len 800");
    mk_entry(e, CA_MSG_ROOT, 801, 0); CHECK(ca_entry_valid(e, CA_MSG_ROOT)==0, "reject der_len 801");
    /* contract validator (0x08051CFE): der_len==32 */
    mk_entry(e, CA_MSG_CONTRACT, 32, 0x5A);
    CHECK(ca_contract_valid(e, CA_MSG_CONTRACT)==1, "valid contract (der_len 32)");
    mk_entry(e, CA_MSG_CONTRACT, 33, 0);
    CHECK(ca_contract_valid(e, CA_MSG_CONTRACT)==0, "reject contract der_len 33");

    /* --- ca_populate: compact NULL-term root ptr array, invalid slots skipped --- */
    static uint8_t data[CA_DATA_MAX];
    memset(data, 0, sizeof data);
    mk_entry(data + 0*808, CA_MSG_ROOT, 100, 0x11);   /* slot0 valid */
    mk_entry(data + 1*808, CA_MSG_OEM,  100, 0x22);   /* slot1 wrong msg_code -> skipped */
    mk_entry(data + 2*808, CA_MSG_ROOT, 200, 0x33);   /* slot2 valid */
    mk_entry(data + 3*808, CA_MSG_ROOT, 0,   0x44);   /* slot3 der_len 0 -> skipped */
    mk_entry(data + 4*808, CA_MSG_ROOT, 300, 0x55);   /* slot4 valid */
    mk_entry(data + 5*808, CA_MSG_PRI_ROOT, 150, 0x66);  /* Pri_root */
    mk_entry(data + 6*808, CA_MSG_OEM, 150, 0x77);       /* Oem */
    mk_entry(data + 9*808, CA_MSG_CONTRACT, 32, 0x88);   /* Contract */
    ca_store_t st; memset(&st, 0, sizeof st);
    uint8_t cnt = ca_populate(&st, data, 10*808);
    CHECK(cnt==3, "populate 3 valid roots (slots 0,2,4)");
    CHECK(st.root_count==3, "root_count 3");
    CHECK(st.root[0].der_len==100 && st.root[0].der[0]==0x11, "compact root[0] = slot0");
    CHECK(st.root[1].der_len==200 && st.root[1].der[0]==0x33, "compact root[1] = slot2");
    CHECK(st.root[2].der_len==300 && st.root[2].der[0]==0x55, "compact root[2] = slot4");
    CHECK(st.root_ptr[0]==(const uint8_t*)&st.root[0].der_len, "ptr[0] = &root[0].der_len (entry+4)");
    CHECK(st.root_ptr[1]==(const uint8_t*)&st.root[1].der_len, "ptr[1] = &root[1].der_len");
    CHECK(st.root_ptr[2]==(const uint8_t*)&st.root[2].der_len, "ptr[2] = &root[2].der_len");
    CHECK(st.root_ptr[3]==0, "ptr array NULL-terminated");
    /* the ptr points at {der_len, DER}: read der_len then DER like the mbedTLS CA-chain loop */
    CHECK(get32(st.root_ptr[0])==100, "ptr[0] deref der_len 100");
    CHECK(st.root_ptr[0][4]==0x11, "ptr[0]+4 = DER start");
    CHECK(st.pri_root_valid==1 && st.pri_root.der_len==150, "Pri_root read+valid");
    CHECK(st.oem_valid==1 && st.oem.der_len==150, "Oem read+valid");
    CHECK(st.contract_valid==1 && st.contract.der_len==32, "Contract read+valid");

    /* empty store -> 0 roots, NULL-term */
    memset(data, 0, sizeof data);
    cnt = ca_populate(&st, data, 5*808);
    CHECK(cnt==0 && st.root_count==0 && st.root_ptr[0]==0, "empty store -> 0 roots NULL-term");

    /* --- ca_store_init via injected read hook: header + checksum + populate --- */
    memset(img, 0, sizeof img);
    img_size = 10*808;
    mk_entry(img + 16 + 0*808, CA_MSG_ROOT, 100, 0x11);
    mk_entry(img + 16 + 1*808, CA_MSG_ROOT, 200, 0x33);
    mk_entry(img + 16 + 2*808, CA_MSG_ROOT, 300, 0x55);
    build_hdr(1, img_size, data_sum(img_size));
    ca_store_set_read(fake_read);
    ca_store_init();
    const ca_store_t *g = ca_store_get();
    CHECK(g->hdr_valid==1, "init hdr valid");
    CHECK(g->cksum_ok==1, "init checksum ok");
    CHECK(g->store_present==1, "init store present");
    CHECK(g->ext_version==1 && g->ext_size==img_size, "init ext version/size");
    CHECK(g->root_count==3, "init 3 roots");
    CHECK(ca_store_root_count()==3, "root_count accessor 3");
    CHECK(g->root_ptr[0]!=0 && g->root_ptr[3]==0, "init ptr array NULL-term");
    CHECK(get32(g->root_ptr[0])==100 && g->root_ptr[0][4]==0x11, "init root[0] {len,DER}");

    /* SDP TLS gate: root_count>0 -> TLS (0x00); the count low-byte feeds sdp_security_select. */
    CHECK((ca_store_root_count() & 0xFF)!=0, "root_count>0 -> SDP requests TLS");

    /* checksum mismatch -> store_present 0, no roots */
    build_hdr(1, img_size, data_sum(img_size) + 1);   /* bad cksum */
    ca_store_init();
    CHECK(ca_store_get()->hdr_valid==1, "bad-cksum hdr still valid");
    CHECK(ca_store_get()->cksum_ok==0, "bad-cksum detected");
    CHECK(ca_store_get()->store_present==0, "bad-cksum -> not present");
    CHECK(ca_store_get()->root_count==0, "bad-cksum -> 0 roots");

    /* bad magic -> hdr invalid, not present */
    put32(img + 0, 0xDEADBEEF);
    ca_store_init();
    CHECK(ca_store_get()->hdr_valid==0 && ca_store_get()->store_present==0, "bad magic -> not present");

    /* version 0 (internal-style) rejected by ext validator */
    build_hdr(0, img_size, data_sum(img_size));
    ca_store_init();
    CHECK(ca_store_get()->hdr_valid==0, "ext version 0 rejected");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}