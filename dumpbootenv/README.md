# Show Boot Environment

This little program shows the values of the general purpose registers after the internal bootrom has loaded and
jumped into bootcode.bin.

## bootcode.bin

The values are:

    r0:  80000200
    r1:  ffffffff
    r2:  7ee02000
    r3:  20000008
    r4:  00000000
    r5:  7e200080
    r6:  00000000
    r7:  00000000
    r8:  00000000
    r9:  00000000
    r10: 00000000
    r11: 00000000
    r12: 00000001
    r13: 00000000
    r14: 000010c0
    r15: 00000000
    r16: 7e000080
    r17: 0001ef40
    r18: 80000000
    r19: 60008124
    r20: 00000000
    r21: 00000000
    r22: 00000000
    r23: 00000000
    r24: 60008000 ; cb - base pointer
    r25: 6000865c ; sp - stack pointer
    r26: 60003602 ; lr - link register
    r27: 00000000
    r28: 00000000 ; ssp
    r29: 00000000
    r30: 2000000a ; sr - status register
    r31: 80000200 ; pc - program counter

According to the BCM2835 ARM Peripherals manual, address ranges are:

    00000000 - 3fffffff  ; L1 and L2 cached
    40000000 - 7fffffff  ; L2 cache coherent (non allocating)
    80000000 - bfffffff  ; L2 cached only
    c0000000 - ffffffff  ; Direct uncached

Therefore bootcode.bin is loaded and executing from the L2 cache at 0x80000000.

## loader.bin

When used in place of the old loader.bin (for the old boot chain that used bootcode.bin to load loader.bin and
then start.elf), the values are:

    r0:  c7400200
    r1:  00000000
    r2:  7ee02000
    r3:  00000002
    r4:  ffffb001
    r5:  7ee02000
    r6:  00000000
    r7:  00000001
    r8:  00000000
    r9:  c7400200
    r10: 00000000
    r11: 00000000
    r12: 00000001
    r13: 00000000
    r14: 000010c0
    r15: 00000000
    r16: 7e000080
    r17: 0001ef40
    r18: 80000000
    r19: 60008124
    r20: 00000000
    r21: 00000000
    r22: 00000000
    r23: 00000000
    r24: 80004000 ; bp
    r25: 8000418c ; sp
    r26: 80000d96 ; lr
    r27: 00000000
    r28: 00000000 ; ssp
    r29: 00000000
    r30: 2000000a ; sr
    r31: c7400200 ; pc
