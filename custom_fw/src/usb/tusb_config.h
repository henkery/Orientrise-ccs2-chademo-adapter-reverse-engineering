/* tusb_config.h — TinyUSB configuration for the custom_fw revert-from-custom USB device CDC console.
 * STM32F427/F429 OTG_FS (DesignWare dwc2, register base 0x50000000), bare-metal (no RTOS), device
 * mode, slave (no DMA). The USB port also charges the internal battery (device/sink VBUS role), so
 * device mode is hardware-feasible (REPORT §5.15c). PLLQ=7 already gives the 48 MHz USB clock (rcc.c).
 */
#ifndef TUSB_CONFIG_H
#define TUSB_CONFIG_H

#define CFG_TUSB_MCU              OPT_MCU_STM32F4
#define CFG_TUSB_OS               OPT_OS_NONE
#define CFG_TUSB_DEBUG            0

/* RHPort0 = OTG_FS, device mode. */
#define CFG_TUSB_RHPORT0_MODE     OPT_MODE_DEVICE

/* Device stack: CDC only (the revert console). */
#define CFG_TUD_ENABLED           1
#define CFG_TUD_CDC               1
#define CFG_TUD_ENDPOINT0_SIZE    64

/* CDC buffers: RX must hold a burst of streamed UPG bytes between tud_task polls; TX holds responses. */
#define CFG_TUD_CDC_RX_BUFSIZE    512
#define CFG_TUD_CDC_TX_BUFSIZE    256
#define CFG_TUD_CDC_EP_BUFSIZE    64

/* dwc2 slave mode (no DMA) — simplest bring-up on OTG_FS. */
#define CFG_TUD_DWC2_DMA_ENABLE   0

/* No VBUS-sense pin (PA9/PA10 are USART1, not OTG_FS_VBUS): force B-valid + NOVBUSSENS so the device
 * does not wait for a VBUS-sense input. The port still accepts VBUS power (it charges the battery). */
#define CFG_TUD_VBUS_DETECT_HW    0

#endif /* TUSB_CONFIG_H */