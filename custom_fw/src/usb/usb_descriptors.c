/* usb_descriptors.c — TinyUSB application descriptor callbacks for the CDC revert console.
 * A single CDC ACM function (comm interface 0 + data interface 1, IAD). Bus-powered device; the port
 * also charges the internal battery. VID/PID use the TinyUSB CDC demo IDs (bench tool, not a product).
 */
#include "tusb.h"

#define USBD_VID          0xCafeu
#define USBD_PID_CDC      0x4004u
#define USBD_MANUFACTURER "Orientrise-RE"
#define USBD_PRODUCT      "Adapter Revert Console"
#define USBD_SERIAL       "0001"

/* Endpoint layout (matches the TinyUSB CDC class driver): notification IN1, data OUT2 / IN2. */
#define EPNOTIF           0x81u
#define EPDATA_OUT        0x02u
#define EPDATA_IN         0x82u
#define EPDATA_SIZE       CFG_TUD_CDC_EP_BUFSIZE

/* ---- Device descriptor ---- */
static const uint8_t desc_device[] = {
    18,                                 /* bLength */
    TUSB_DESC_DEVICE,                   /* bDescriptorType */
    0x00, 0x02,                         /* bcdUSB 2.0 */
    0xEF,                               /* bDeviceClass    (misc, IAD) */
    0x02,                               /* bDeviceSubClass (common) */
    0x01,                               /* bDeviceProtocol (IAD) */
    CFG_TUD_ENDPOINT0_SIZE,             /* bMaxPacketSize0 */
    (uint8_t)(USBD_VID & 0xFFu), (uint8_t)(USBD_VID >> 8),
    (uint8_t)(USBD_PID_CDC & 0xFFu), (uint8_t)(USBD_PID_CDC >> 8),
    0x00, 0x01,                         /* bcdDevice 1.0 */
    0x01,                               /* iManufacturer */
    0x02,                               /* iProduct */
    0x03,                               /* iSerialNumber */
    0x01                                /* bNumConfigurations */
};

uint8_t const *tud_descriptor_device_cb(void)
{
    return desc_device;
}

/* ---- Configuration descriptor (CDC ACM, total 75 bytes) ---- */
#define CONFIG_TOTAL_LEN  75u
static const uint8_t desc_config[] = {
    /* Configuration */
    9, TUSB_DESC_CONFIGURATION,
    (uint8_t)(CONFIG_TOTAL_LEN & 0xFFu), (uint8_t)(CONFIG_TOTAL_LEN >> 8),
    2,                                  /* bNumInterfaces */
    1,                                  /* bConfigurationValue */
    0,                                  /* iConfiguration */
    0x80,                               /* bmAttributes: bus-powered */
    100,                                /* bMaxPower: 200 mA */

    /* Interface Association Descriptor (CDC function, interfaces 0..1) */
    8, TUSB_DESC_INTERFACE_ASSOCIATION,
    0,                                  /* bFirstInterface */
    2,                                  /* bInterfaceCount */
    0x02,                               /* bFunctionClass: CDC */
    0x02,                               /* bFunctionSubClass: ACM */
    0x00,                               /* bFunctionProtocol */
    0,                                  /* iFunction */

    /* Communication interface (0) */
    9, TUSB_DESC_INTERFACE,
    0,                                  /* bInterfaceNumber */
    0,                                  /* bAlternateSetting */
    1,                                  /* bNumEndpoints */
    0x02,                               /* bInterfaceClass: CDC */
    0x02,                               /* bInterfaceSubClass: ACM */
    0x00,                               /* bInterfaceProtocol */
    0,                                  /* iInterface */
    /* CDC header functional descriptor */
    5, 0x24, 0x00, 0x10, 0x01,          /* bcdCDC 1.10 */
    /* CDC call management functional descriptor */
    5, 0x24, 0x01, 0x00, 0x01,          /* bmCapabilities 0, bDataInterface 1 */
    /* CDC ACM functional descriptor */
    4, 0x24, 0x02, 0x02,                /* bmCapabilities: line coding + serial state */
    /* CDC union functional descriptor */
    5, 0x24, 0x06, 0x00, 0x01,          /* bMasterInterface 0, bSlaveInterface 1 */
    /* Notification endpoint (IN1, interrupt) */
    7, TUSB_DESC_ENDPOINT,
    EPNOTIF, 0x03, 8, 0, 16,

    /* Data interface (1) */
    9, TUSB_DESC_INTERFACE,
    1,                                  /* bInterfaceNumber */
    0,                                  /* bAlternateSetting */
    2,                                  /* bNumEndpoints */
    0x0A,                               /* bInterfaceClass: CDC data */
    0x00,                               /* bInterfaceSubClass */
    0x00,                               /* bInterfaceProtocol */
    0,                                  /* iInterface */
    /* Data OUT endpoint (OUT2, bulk) */
    7, TUSB_DESC_ENDPOINT,
    EPDATA_OUT, 0x02, (uint8_t)(EPDATA_SIZE & 0xFFu), (uint8_t)(EPDATA_SIZE >> 8), 0,
    /* Data IN endpoint (IN2, bulk) */
    7, TUSB_DESC_ENDPOINT,
    EPDATA_IN, 0x02, (uint8_t)(EPDATA_SIZE & 0xFFu), (uint8_t)(EPDATA_SIZE >> 8), 0
};

uint8_t const *tud_descriptor_configuration_cb(uint8_t index)
{
    (void)index;
    return desc_config;
}

/* ---- String descriptors ---- */
static const uint16_t desc_string0[] = { 0x0409 };   /* langid: US English */

static uint16_t desc_string[32];
uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
    (void)langid;
    if (index == 0)
        return desc_string0;

    const char *s;
    switch (index) {
    case 1: s = USBD_MANUFACTURER; break;
    case 2: s = USBD_PRODUCT;      break;
    case 3: s = USBD_SERIAL;       break;
    default: return NULL;
    }

    uint8_t n = 0;
    while (s[n] && n < 31)
        n++;
    desc_string[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * n + 2));
    for (uint8_t i = 0; i < n; i++)
        desc_string[1 + i] = (uint16_t)s[i];
    return desc_string;
}