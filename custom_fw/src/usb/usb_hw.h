/* usb_hw.h — STM32F4 OTG_FS device bring-up for the TinyUSB CDC revert console (REPORT §5.15c).
 * Enables the OTG_FS clock + PA11/PA12 (DM/DP) AF10 and initializes the TinyUSB device stack. The
 * 48 MHz USB clock is already provided by rcc.c (PLLQ=7). No VBUS-sense pin (PA9/PA10 = USART1); the
 * dwc2 driver forces B-valid + NOVBUSSENS (CFG_TUD_VBUS_DETECT_HW=0). The OTG_FS IRQ (67) is wired to
 * tud_int_handler in usb_hw.c and enabled by the stack. The clone FS PHY needs VBUSASEN/VBUSBSEN/
 * SOFOUTEN powered to decode packets — handled by the vendored dwc2_stm32.h gccfg patch.
 */
#ifndef USB_HW_H
#define USB_HW_H

/* Bring up OTG_FS device mode + TinyUSB (tud_init). Call after rcc_init. */
void usb_hw_init(void);

#endif /* USB_HW_H */