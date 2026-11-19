#!/usr/bin/env python3
"""analyze74.py — GPIO pin-map decoder (REPORT §8.4).

The board GPIO init function @ runtime 0x08087010 (f+0x67412, found via analyze72 + pool-location
xref hunt) writes a literal pool of STANDARD STM32F4 GPIO register values per port (GPIOA..E),
then calls the GPIO-lock helper @0x08087340 (f+0x67742, LCKR key sequence) with mask 0xFFFF.
The "packed config table" at f+0x67756 is just that literal pool — NOT a custom format. This tool
encodes the per-port register values extracted from the init disassembly (analyze72.py firmware.bin
0x67400 0x674d0) and decodes every pin: MODER (mode), AFR (alternate function), OTYPER (open-drain),
PUPDR (pull), ODR (initial output level), and maps AF numbers to STM32F427/429 peripheral functions.

Register offsets: MODER+0x00 OTYPER+0x04 OSPEEDR+0x08 PUPDR+0x0C ODR+0x14 AFR0+0x20 AFR1+0x24.
MODER/PUPDR/OSPEEDR: 2 bits/pin; OTYPER: 1 bit/pin; AFR: 4 bits/pin (AFR0 pins0-7, AFR1 pins8-15).

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze74.py'
"""
# Per-port register values extracted from the GPIO init @0x08087010 (f+0x67412..0x674CE).
# OSPEEDR for B/C/D = 0xAAAAAAAA (mov.w r5,#-0x55555556); r4=0 (AFR0/1 zero writes).
PORTS = {
 'GPIOA': dict(base=0x40020000, MODER=0x02A8A93F, OTYPER=0x00000447, OSPEEDR=0xABEAEFAA,
               PUPDR=0x00146100, ODR=0x00000457, AFR0=0x55500000, AFR1=0x000AA770),
 'GPIOB': dict(base=0x40020400, MODER=0x5050000F, OTYPER=0x00008003, OSPEEDR=0xAAAAAAAA,
               PUPDR=0x02010020, ODR=0x0000C003, AFR0=0x00000000, AFR1=0x00000000),
 'GPIOC': dict(base=0x40020800, MODER=0x00040430, OTYPER=0x00000204, OSPEEDR=0xAAAAAAAA,
               PUPDR=0x00010200, ODR=0x00000204, AFR0=0x00000000, AFR1=0x00000000),
 'GPIOD': dict(base=0x40020C00, MODER=0x0241004A, OTYPER=0x00001009, OSPEEDR=0xAAAAAAAA,
               PUPDR=0x01280005, ODR=0x00001009, AFR0=0x00000099, AFR1=0x00020000),
 'GPIOE': dict(base=0x40021000, MODER=0x6A414100, OTYPER=0x00002000, OSPEEDR=0xBBEAAAAA,
               PUPDR=0x54500000, ODR=0x0000A810, AFR0=0x00000000, AFR1=0x05550000),
}
MODE = {0:'IN', 1:'OUT', 2:'AF', 3:'ANA'}
PULL = {0:'--', 1:'PU', 2:'PD', 3:'rsv'}
# STM32F427/429 alternate-function map (AF0..AF15), abbreviated to the peripherals this board uses.
AF_FUNC = {
 0:'SYS', 1:'TIM1/2', 2:'TIM3/4/5', 3:'TIM8/9/10/11', 4:'I2C1/2/3', 5:'SPI1/SPI2',
 6:'SPI3', 7:'SPI2/USART1/2/3', 8:'USART4/5/6/UART7/8', 9:'CAN1/CAN2/TIM12/13/14',
 10:'USB_OTG_FS/HS', 11:'ETH', 12:'FMC/SDIO/OTG_HS_FS', 13:'DCMI', 14:'(LTDC/resv)', 15:'EVENTOUT',
}
# Specific pin AF assignments (STM32F427 datasheet) for the AF pins this init configures.
PIN_AF = {
 ('GPIOA',5):'SPI1_SCK', ('GPIOA',6):'SPI1_MISO', ('GPIOA',7):'SPI1_MOSI',
 ('GPIOA',9):'USART1_TX', ('GPIOA',10):'USART1_RX',
 ('GPIOA',11):'USB_OTG_FS_DM', ('GPIOA',12):'USB_OTG_FS_DP',
 ('GPIOD',0):'CAN1_RX', ('GPIOD',1):'CAN1_TX', ('GPIOD',12):'TIM4_CH1',
 ('GPIOE',12):'SPI4_SCK', ('GPIOE',13):'SPI4_MISO', ('GPIOE',14):'SPI4_MOSI',
}
def bits(v, n, w): return (v >> (n*w)) & ((1<<w)-1)
print("GPIO pin map — decoded from board init @0x08087010 (f+0x67412), REPORT §8.4")
print("mode: IN=input OUT=output AF=alternate ANA=analog; pull PU/PD; OD=open-drain; lvl=initial ODR")
for name, r in PORTS.items():
    print(f"\n== {name} (0x{r['base']:08X}) ==")
    print("  pin  mode  AF  function            pull  OD  lvl")
    for p in range(16):
        m = bits(r['MODER'], p, 2)
        af = bits(r['AFR0'] if p < 8 else r['AFR1'], p % 8, 4)
        pull = bits(r['PUPDR'], p, 2)
        od = bits(r['OTYPER'], p, 1)
        lvl = bits(r['ODR'], p, 1)
        func = ''
        if m == 2:
            func = PIN_AF.get((name, p), AF_FUNC.get(af, f'AF{af}'))
        elif m == 3:
            func = 'ADC/analog'
        elif m == 1:
            func = 'GPIO-out'
        afstr = f'{af:2d}' if m == 2 else ' -'
        print(f"  P{name[-1]}{p:<2d} {MODE[m]:4s} {afstr}  {func:18s}  {PULL[pull]:3s}  {od}   {lvl}")
print("\n== summary of bus pins ==")
print("  SPI1 (QCA7005 PLC modem): PA5=SCK PA6=MISO PA7=MOSI (AF5)")
print("  SPI4 (storage flash):     PE12=SCK PE13=MISO PE14=MOSI (AF5)")
print("  USART1:                   PA9=TX PA10=RX (AF7)")
print("  USB OTG FS:               PA11=DM PA12=DP (AF10)")
print("  CAN1:                     PD0=RX PD1=TX (AF9)")
print("  TIM4_CH1:                 PD12 (AF2)")
print("  ADC analog:               PA0/1/2, PB0/1, PC2")
print("  CAN2: no AF9 pins in THIS init (PB5/6/12/13 left input) — assigned elsewhere or unused; pending")