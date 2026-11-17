import sys, struct, collections, re
dec=open(sys.argv[1],'rb').read(); n=len(dec)

# STM32F4 / GD32F4 peripheral bases
periph={
 0x40023800:"RCC",0x40023c00:"FLASH_R",0x40007000:"PWR",0x40013800:"SYSCFG",
 0x40013c00:"EXTI",0x40020000:"GPIOA",0x40020400:"GPIOB",0x40020800:"GPIOC",
 0x40021000:"GPIOD",0x40021400:"GPIOE",0x40021800:"GPIOF",0x40021c00:"GPIOG",
 0x40022000:"GPIOH",0x40022400:"GPIOI",0x40013000:"SPI1",0x40003800:"SPI2",
 0x40003c00:"SPI3",0x40011000:"USART1",0x40004400:"USART2",0x40004800:"USART3",
 0x40004c00:"UART4",0x40005000:"UART5",0x40011400:"USART6",0x40006400:"CAN1",
 0x40006800:"CAN2",0x40000000:"TIM2",0x40000400:"TIM3",0x40000800:"TIM4",
 0x40000c00:"TIM5",0x40010000:"TIM1",0x40010400:"TIM8",0x40002800:"IWDG",
 0x40002c00:"WWDG",0x40002000:"ADC1",0x40002100:"ADC2",0x40002200:"ADC3",
 0x40002300:"ADC_common",0x40005400:"I2C1",0x40005800:"I2C2",0x40005c00:"I2C3",
 0x40023000:"CRC",0x40007400:"DAC",0x40012c00:"DMA?" ,0x40023700:"DMA1?",
 0x40026000:"DMA2?",0x40026400:"DMA2?",0xE000E010:"SysTick",0xE000ED00:"SCB",
 0xE000E100:"NVIC",0x40015800:"?",0x4000a000:"?",0x50000000:"USB_OTG_FS",
 0x40040000:"USB_OTG_HS",0x40028000:"ETH_MAC",0x40029000:"ETH_MMC",
}
# count exact 32-bit occurrences (any alignment) to catch literal loads
cnt=collections.Counter(); first={}
for off in range(0,n-4):
    w=struct.unpack_from('<I',dec,off)[0]
    if w in periph:
        cnt[w]+=1; first.setdefault(w,off)
print("== exact peripheral-base occurrences ==")
for w,name in sorted(periph.items()):
    if cnt[w]:
        print(f"0x{w:08x} {name:12s} x{cnt[w]:3d} first@0x{first[w]:06x}")

print("\n== flash pointer values: top exact values (to infer link base) ==")
fc=collections.Counter(); ffirst={}
for off in range(0,n-4,4):
    w=struct.unpack_from('<I',dec,off)[0]
    if 0x08000000<=w<0x08100000:
        fc[w]+=1; ffirst.setdefault(w,off)
for w,c in fc.most_common(20):
    print(f"0x{w:08x} x{c:3d} first@0x{ffirst[w]:06x}")

print("\n== context: BOOT string & update mechanism ==")
for m in re.finditer(rb'BOOT[\x20-\x7e]{0,40}',dec):
    print(f"0x{m.start():06x}: {m.group()!r}")
for pat in [b"need update", b"IAP", b"jump", b"Jump", b"0x0802", b"app", b"APP"]:
    for m in list(re.finditer(re.escape(pat),dec))[:3]:
        i=m.start();ctx=dec[max(0,i-10):i+len(pat)+20]
        ctx=''.join(chr(x) if 32<=x<127 else '.' for x in ctx)
        print(f"{pat!r} @0x{i:06x}: {ctx!r}")