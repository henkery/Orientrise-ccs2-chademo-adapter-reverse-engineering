import sys, struct, re, collections

dec=open(sys.argv[1],'rb').read()
n=len(dec)

print("== header fields ==")
hdr=dec[:0x58]
for line in hdr.split(b'\r\n'):
    if line: print(repr(line))

print("\n== bytes at 0x58 (firmware start?) ==")
b=dec[0x58:0x88]
print(' '.join(f'{x:02x}' for x in b))
w=struct.unpack_from('<8I',dec,0x58)
print("as words:", ' '.join(f'0x{x:08x}' for x in w))

print("\n== broad vector-table scan ==")
hits=[]
for off in range(0,n-32,4):
    sp=struct.unpack_from('<I',dec,off)[0]
    if 0x20000000<=sp<0x20100000:
        cnt=0
        for k in range(1,10):
            wv=struct.unpack_from('<I',dec,off+4*k)[0]
            if wv&1 and 0x00000000<wv<0x20000000: cnt+=1
            else: break
        if cnt>=4:
            hits.append((off,sp,cnt))
for off,sp,cnt in hits[:20]:
    rv=struct.unpack_from('<I',dec,off+4)[0]
    print(f"off 0x{off:06x}: SP=0x{sp:08x} reset=0x{rv:08x} run={cnt}")
print(f"total {len(hits)}")

print("\n== identifier strings (chip/rtos/proto) ==")
pats=[b"STM32",b"GD32",b"FreeRTOS",b"RT-Thread",b"rtthread",b"lwIP",b"lwip",b"mbedTLS",b"mbedtls",b"QCA",b"AR7420",b"INT6",b"HomePlug",b"GreenPHY",b"CHAdeMO",b"chademo",b"CAN",b"ISO15118",b"DIN70121",b"DIN",b"GBT",b"GB/T",b"XIE",b"Orient",b"ORIENT",b"KM-",b"USART",b"SPI",b"I2C",b"ADC",b"PWM",b"relay",b"Relay",b"CP",b"PP",b"proximity",b"pilot"]
for p in pats:
    idxs=[m.start() for m in re.finditer(re.escape(p),dec)]
    if idxs:
        # show context of first hit
        i=idxs[0]
        ctx=dec[max(0,i-8):i+len(p)+16]
        ctx=''.join(chr(x) if 32<=x<127 else '.' for x in ctx)
        print(f"{p.decode():12s} x{len(idxs):4d} first@0x{i:06x}: {ctx!r}")