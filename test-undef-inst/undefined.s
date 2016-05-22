//-------------------------------------------------------------------------
// VideoCore IV undefined instructions for VC4 / Raspberry Pi
//-------------------------------------------------------------------------
//
// This program tries executing all those (scalar) VC4 instructions which
// are suspected to raise exception 3 (undefined instruction).
//
// An exception handler is in place to trace the exceptions raised.
//
// This program should be run in place of bootcode.bin.
//
// It outputs to UART1 at 115200 baud.
//
// Last updated: 22 May 2016.
//-------------------------------------------------------------------------
  // Rename and run as bootcode.bin
  START("undefined.bin");

  // Because of the low system clock rate, this baud rate might be inaccurate
  // So be careful with your serial/terminal, some adjustment may be necessary.
#ifdef TURBO_SERIAL
  equ(TARGET_BAUD_RATE, 1200000);
#else
  equ(TARGET_BAUD_RATE, 115200);
#endif

  // System clock is running directly off the 19.2MHz crystal at initial reset
  equ(SYSTEM_CLOCK, 19200000);

  // GPIO MMIO
  equ(GPFSEL1, 0x7e200004);
  equ(GPSET0, 0x7e20001C);
  equ(GPCLR0, 0x7e200028);
  equ(GPPUD, 0x7e200094);
  equ(GPPUDCLK0, 0x7e200098);

  // UART1 MMIO
  equ(AUX_ENABLES, 0x7e215004);
  equ(AUX_MU_IO_REG, 0x7e215040);
  equ(AUX_MU_IER_REG, 0x7e215044);
  equ(AUX_MU_IIR_REG, 0x7e215048);
  equ(AUX_MU_LCR_REG, 0x7e21504C);
  equ(AUX_MU_MCR_REG, 0x7e215050);
  equ(AUX_MU_LSR_REG, 0x7e215054);
  equ(AUX_MU_MSR_REG, 0x7e215058);
  equ(AUX_MU_SCRATCH, 0x7e21505C);
  equ(AUX_MU_CNTL_REG, 0x7e215060);
  equ(AUX_MU_STAT_REG, 0x7e215064);
  equ(AUX_MU_BAUD_REG, 0x7e215068);

  // Forward declarations
  declare(uart_init);
  declare(uart_putchars);
  declare(uart_putcrlf);
  declare(uart_puthexword);
  declare(led_flash);

  // Forward declarations of exception handlers
  declare(exceptions[0x80]);
  //
  // 0x00 zero
  // 0x01 misaligned memory access
  // 0x02 division by zero
  // 0x03 undefined instruction
  // 0x04 forbidden instruction
  // 0x05 illegal memory
  // 0x06 bus error
  // 0x07 floating point
  // 0x08 isp
  // 0x09 dummy
  // 0x0a icache
  // 0x0b vec core
  // 0x0c bad l2 alias
  // 0x0d breakpoint
  // ...
  // 0x20 software exception 0
  // 0x21 software exception 1
  // 0x22 software exception 2
  // 0x23 software exception 3
  // 0x24 software exception 4
  // 0x25 software exception 5
  // 0x26 software exception 6
  // 0x27 software exception 7
  // 0x28 software exception 8
  // 0x29 software exception 9
  // 0x2a software exception 10
  // 0x2b software exception 11
  // 0x2c software exception 12
  // 0x2d software exception 13
  // 0x2e software exception 14
  // 0x2f software exception 15
  // 0x30 software exception 16
  // 0x31 software exception 17
  // 0x32 software exception 18
  // 0x33 software exception 19
  // 0x34 software exception 20
  // 0x35 software exception 21
  // 0x36 software exception 22
  // 0x37 software exception 23
  // 0x38 software exception 24
  // 0x39 software exception 25
  // 0x3a software exception 26
  // 0x3b software exception 27
  // 0x3c software exception 28
  // 0x3d software exception 29
  // 0x3e software exception 30
  // 0x3f software exception 31

  // Exception table at 0x80000000
  org(0x80000000);

  // Define the table of exception vectors to exception handlers
  for (int i=0; i<0x80; i++)
    dc(exceptions[i]);

  // Code starts at 0x80000200

  // Set up exception vector
  movi(r0, 0x80000000); movi(r1, 0x7e002030); st(r0, r1);
  movi(r0, 0x80000000); movi(r1, 0x7e002830); st(r0, r1);

  // Set up SSP
  movi(r28, 0x80010000);

  bl(uart_init);

  // Print \r\n\r\n**\r\n
  movi(r0, '\r'<<0|'\n'<<8|'\r'<<16|'\n'<<24); bl(uart_putchars);
  movi(r0, '*'<<0|'*'<<8|'\r'<<16|'\n'<<24); bl(uart_putchars);

  // load registers with known patterns
  for (int i=0; i<29; i++)
    if (i != 28)
      movi(r0+i, 0xbabe0000+i);

// TEST instruction report:
//  INS <instruction> <sr>
//  [<exception-report>]
//  INS <instruction> <sr>

#define TEST(x) \
  mov(r16,r0); mov(r17,r1); mov(r18,r2); mov(r19,r3); \
  movi(r0, 'I'|'N'<<8|'S'<<16|' '<<24); bl(uart_putchars); \
  movi(r0, x); bl(uart_puthexword); \
  movi(r0, ' '); bl(uart_putchars); \
  mov(r0, sr); bl(uart_puthexword); \
  mov(r0,r16); mov(r1,r17); mov(r2,r18); mov(r3,r19); \
  emit1(x); nop(); nop(); nop(); nop(); nop(); \
  mov(r16,r0); mov(r17,r1); mov(r18,r2); mov(r19,r3); \
  bl(uart_putcrlf); \
  movi(r0, 'I'|'N'<<8|'S'<<16|' '<<24); bl(uart_putchars); \
  movi(r0, x); bl(uart_puthexword); \
  movi(r0, ' '); bl(uart_putchars); \
  mov(r0, sr); bl(uart_puthexword); \
  bl(uart_putcrlf); \
  bl(uart_putcrlf); \
  mov(r0,r16); mov(r1,r17); mov(r2,r18); mov(r3,r19);

#define TEST2(x, y) \
  mov(r16,r0); mov(r17,r1); mov(r18,r2); mov(r19,r3); \
  movi(r0, 'I'|'N'<<8|'S'<<16|' '<<24); bl(uart_putchars); \
  movi(r0, x); bl(uart_puthexword); \
  movi(r0, ' '); bl(uart_putchars); \
  mov(r0, sr); bl(uart_puthexword); \
  mov(r0,r16); mov(r1,r17); mov(r2,r18); mov(r3,r19); \
  emit1(x); emit1(y); nop(); nop(); nop(); nop(); \
  mov(r16,r0); mov(r17,r1); mov(r18,r2); mov(r19,r3); \
  bl(uart_putcrlf); \
  movi(r0, 'I'|'N'<<8|'S'<<16|' '<<24); bl(uart_putchars); \
  movi(r0, x); bl(uart_puthexword); \
  movi(r0, ' '); bl(uart_putchars); \
  mov(r0, sr); bl(uart_puthexword); \
  bl(uart_putcrlf); \
  bl(uart_putcrlf); \
  mov(r0,r16); mov(r1,r17); mov(r2,r18); mov(r3,r19);

#define TEST3(x, y, z) \
  mov(r16,r0); mov(r17,r1); mov(r18,r2); mov(r19,r3); \
  movi(r0, 'I'|'N'<<8|'S'<<16|' '<<24); bl(uart_putchars); \
  movi(r0, x); bl(uart_puthexword); \
  movi(r0, ' '); bl(uart_putchars); \
  mov(r0, sr); bl(uart_puthexword); \
  mov(r0,r16); mov(r1,r17); mov(r2,r18); mov(r3,r19); \
  emit1(x); emit1(y); emit1(z); nop(); nop(); nop(); nop(); \
  mov(r16,r0); mov(r17,r1); mov(r18,r2); mov(r19,r3); \
  bl(uart_putcrlf); \
  movi(r0, 'I'|'N'<<8|'S'<<16|' '<<24); bl(uart_putchars); \
  movi(r0, x); bl(uart_puthexword); \
  movi(r0, ' '); bl(uart_putchars); \
  mov(r0, sr); bl(uart_puthexword); \
  bl(uart_putcrlf); \
  bl(uart_putcrlf); \
  mov(r0,r16); mov(r1,r17); mov(r2,r18); mov(r3,r19);


  //
  // 16 bit instructions
  //

  // 0000 0000 0000 0000  bkpt
  // 0000 0000 0000 0001  nop
  // 0000 0000 0000 0010  sleep
  // 0000 0000 0000 0011  user
  // 0000 0000 0000 0100  ei
  // 0000 0000 0000 0101  di
  // 0000 0000 0000 0110  cbclr
  // 0000 0000 0000 0111  cbinc
  // 0000 0000 0000 1000  cbchg
  // 0000 0000 0000 1001  cbdec
  // 0000 0000 0000 1010  rti

  // 0000 0000 0000 1xxx
  //
  // 0000 0000 0000 1011  exception 3
  TEST(0x000b);
  // 0000 0000 0000 1100  exception 3
  TEST(0x000c);
  // 0000 0000 0000 1101  exception 3
  TEST(0x000d);
  // 0000 0000 0000 1110  exception 3
  TEST(0x000e);
  // 0000 0000 0000 1111  exception 3
  TEST(0x000f);

  // 0000 0000 0001 xxxx  exception 3
  TEST(0x0010);
  TEST(0x0011);
  TEST(0x0012);
  TEST(0x0013);
  TEST(0x0014);
  TEST(0x0015);
  TEST(0x0016);
  TEST(0x0017);
  TEST(0x0018);
  TEST(0x0019);
  TEST(0x001a);
  TEST(0x001b);
  TEST(0x001c);
  TEST(0x001d);
  TEST(0x001e);
  TEST(0x001f);

  // 0000 0000 001d dddd  swi rd
  // 0000 0000 01ld dddd  b rd
  // 0000 0000 01ld dddd  bl rd
  // 0000 0000 100d dddd  tbb rd
  // 0000 0000 101d dddd  tbh rd
  // 0000 0000 110d dddd  unknown rd
  // 0000 0000 111d dddd  mov rd, cpuid

  // 0000 0001 000d dddd  exception 3
  TEST(0x0100);
  TEST(0x011e);
  TEST(0x011f);

  // 0000 0001 001d dddd  exception 3
  TEST(0x0120);
  TEST(0x013e);
  TEST(0x013f);

  // 0000 0001 010d dddd  unknown rd
  // 0000 0001 011d dddd  unknown rd
  // 0000 0001 10xd dddd  unknown rd
  // 0000 0001 11uu uuuu  swi 0x%02{i}
  // 0000 0010 0bbn nnnn  pop  r%d{b*8}-r%d{(n+b*8)&31} 
  // 0000 0010 1bbn nnnn  push r%d{b*8}-r%d{(n+b*8)&31} 
  // 0000 0011 0bbn nnnn  pop  r%d{b*8}-r%d{(n+b*8)&31}, pc 
  // 0000 0011 1bbn nnnn  push r%d{b*8}-r%d{(n+b*8)&31}, lr 
  // 0000 010u uuuu dddd  ld r%i{d}, 0x%02x{u*4}(sp) 
  // 0000 011u uuuu dddd  st r%i{d}, 0x%02x{u*4}(sp) 
  // 0000 1ww0 ssss dddd  ld%s{w} r%i{d}, (r%i{s}) 
  // 0000 1ww1 ssss dddd  st%s{w} r%i{d}, (r%i{s}) 
  // 0001 0ooo ooo1 1001  add sp, #0x%x{o*4} 
  // 0001 0ooo oood dddd  lea r%i{d}, 0x%x{o*4}(sp) 
  // 0001 1ccc cooo oooo  b%s{c} 0x%08x{$+o*2} 
  // 0011 uuuu ssss dddd  st  r%i{d}, 0x%02x{u*4}(r%i{s}) 
  // 010p pppp ssss dddd  %s{p} r%i{d}, r%i{s} 
  // 0101 0xxs ssss dddd  addscale r%i{d}, r%i{s} lsl %i{x} 
  // 011q qqqu uuuu dddd  %s{q} r%i{d}, #%i{u} 

  //
  // 32 bit instructions
  //

  // 1000 cccc 0000 dddd 01ss ssoo oooo oooo  b%s{c} r%i{d}, r%i{s}, 0x%08x{$+o*2}
  // 1000 cccc 0000 dddd 11uu uuuu oooo oooo  b%s{c} r%i{d}, #%i{u}, 0x%08x{$+o*2}
  // 
  // 1000 cccc aaaa dddd 00ss ssoo oooo oooo  addcmpb%s{c} r%i{d}, r%i{a}, r%i{s}, 0x%08x{$+o*2}
  // 1000 cccc iiii dddd 01ss ssoo oooo oooo  addcmpb%s{c} r%i{d}, #%i{i}, r%i{s}, 0x%08x{$+o*2}
  // 1000 cccc aaaa dddd 10uu uuuu oooo oooo  addcmpb%s{c} r%i{d}, r%i{a}, #%i{u}, 0x%08x{$+o*2}
  // 1000 cccc iiii dddd 11uu uuuu oooo oooo  addcmpb%s{c} r%i{d}, #%i{i}, #%i{u}, 0x%08x{$+o*2}
  // 
  // 1001 cccc 0ooo oooo oooo oooo oooo oooo  b%s{c} 0x%08x{$+o*2}
  // 1001 oooo 1ooo oooo oooo oooo oooo oooo  bl  0x%08x{$+o*2}
  // 
  // # Conditional Ld/St with (ra, rb)
  // 1010 0000 ww0d dddd aaaa accc c00b bbbb  ld%s{w}%s{c} r%i{d}, (r%i{a}, r%i{b})
  // 1010 0000 ww1d dddd aaaa accc c00b bbbb  st%s{w}%s{c} r%i{d}, (r%i{a}, r%i{b})

  // instructions will be doing ld/st r2, (r1, r0) before they trap as illegal so make sure there is a good address
  movi(r0, 0x80000200); movi(r1, 0x0);

  // 1010 0000 xxxx xxxx xxxx xxxx xxxx xxxx
  // 1010 0000 ww0d dddd aaaa accc cXXu uuuu  exception 3
  TEST2(0xa002, 0x0721);
  TEST2(0xa002, 0x0741);
  TEST2(0xa002, 0x0761);

  // 1010 0000 ww1d dddd aaaa accc cXXu uuuu  exception 3
  TEST2(0xa022, 0x0741);
  TEST2(0xa022, 0x0721);
  TEST2(0xa022, 0x0761);

  // 1010 0001 xxxx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xa100, 0x0000);

  // 1010 001o ww0d dddd ssss sooo oooo oooo  ld%s{w} r%i{d}, 0x%x{o}(r%i{s})
  // 1010 001o ww1d dddd ssss sooo oooo oooo  st%s{w} r%i{d}, 0x%x{o}(r%i{s})
  // 1010 0100 ww0d dddd ssss sccc c000 0000  ld%s{w}%s{c} r%i{d}, --(r%i{s})
  // 1010 0100 ww1d dddd ssss sccc c000 0000  st%s{w}%s{c} r%i{d}, --(r%i{s})

  // 1010 0100 ww0d dddd ssss sccc cxxx xxxx  exception 3
  TEST2(0xa402, 0x0001);

  // 1010 0101 ww0d dddd ssss sccc c000 0000  ld%s{w}%s{c} r%i{d}, (r%i{s})++
  // 1010 0101 ww1d dddd ssss sccc c000 0000  st%s{w}%s{c} r%i{d}, (r%i{s})++

  // 1010 0101 xxxx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xa502, 0x0000);

  // 1010 01xx xxxx xxxx xxxx xxxx xxxx xxxx  exception 3
  // 1010 011o ww0d dddd ssss sooo oooo oooo  exception 3
  // 1010 011o ww1d dddd ssss sooo oooo oooo  exception 3
  TEST2(0xa602, 0x0000);

  // 1010 1000 ww0d dddd oooo oooo oooo oooo  ld%s{w} r%i{d}, 0x%0x{o}(r24)
  // 1010 1000 ww1d dddd oooo oooo oooo oooo  st%s{w} r%i{d}, 0x%0x{o}(r24)
  // 1010 1001 ww0d dddd oooo oooo oooo oooo  ld%s{w} r%i{d}, 0x%0x{o}(sp)
  // 1010 1001 ww1d dddd oooo oooo oooo oooo  st%s{w} r%i{d}, 0x%0x{o}(sp)
  // 1010 1010 ww0d dddd oooo oooo oooo oooo  ld%s{w} r%i{d}, 0x%0x{o}(pc)
  // 1010 1010 ww1d dddd oooo oooo oooo oooo  st%s{w} r%i{d}, 0x%0x{o}(pc)
  // 1010 1011 ww0d dddd oooo oooo oooo oooo  ld%s{w} r%i{d}, 0x%x{o}(r0)
  // 1010 1011 ww1d dddd oooo oooo oooo oooo  st%s{w} r%i{d}, 0x%x{o}(r0)

  // 1010 11xx xxxx xxxx xxxx xxxx xxxx xxxx  
  // 1010 11xx ww0d dddd oooo oooo oooo oooo  exception 3
  // 1010 11xx ww1d dddd oooo oooo oooo oooo  exception 3
  TEST2(0xac00, 0x0000);

  // 1011 00pp pppd dddd iiii iiii iiii iiii  %s{p} r%i{d}, #0x%04x{i}
  // 1011 01ss sssd dddd iiii iiii iiii iiii  lea r%i{d}, 0x%04x{i}(r%i{s})

  // 1011 10xx xxxd dddd xxxx xxxx xxxx xxxx  exception 3
  // 1011 1000 000d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xb800, 0x0000);
  // 1011 1011 111d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbbe0, 0x0000);

  // 1011 11xx xxxd dddd xxxx xxxx xxxx xxxx  exception 3
  // 1011 1100 000d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbc00, 0x0000);
  // 1011 1100 001d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbc20, 0x0000);
  // 1011 1100 010d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbc40, 0x0000);
  // 1011 1100 011d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbc60, 0x0000);
  // 1011 1100 100d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbc80, 0x0000);
  // 1011 1100 101d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbca0, 0x0000);
  // 1011 1100 110d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbcc0, 0x0000);
  // 1011 1100 111d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbce0, 0x0000);
  // 1011 1101 000d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbd00, 0x0000);
  // 1011 1110 000d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbe00, 0x0000);
  // 1011 1111 000d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbf00, 0x0000);
  // 1011 1111 100d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbf80, 0x0000);
  // 1011 1111 101d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbfa0, 0x0000);
  // 1011 1111 110d dddd xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xbfc0, 0x0000);

  // 1011 1111 111d dddd oooo oooo oooo oooo  lea r%i{d}, 0x%08x{$+o} ;pc

  // 1100 00pp pppd dddd aaaa accc c00b bbbb  %s{p}%s{c} r%i{d}, r%i{a}, r%i{b}
  // 1100 00pp pppd dddd aaaa accc c1ii iiii  %s{p}%s{c} r%i{d}, r%i{a}, #%i{i}
  // 1100 0100 000d dddd aaaa accc c00b bbbb  mulhd%s{c}.ss r%i{d}, r%i{a}, r%i{b}
  // 1100 0100 001d dddd aaaa accc c00b bbbb  mulhd%s{c}.su r%i{d}, r%i{a}, r%i{b}
  // 1100 0100 010d dddd aaaa accc c00b bbbb  mulhd%s{c}.us r%i{d}, r%i{a}, r%i{b}
  // 1100 0100 011d dddd aaaa accc c00b bbbb  mulhd%s{c}.uu r%i{d}, r%i{a}, r%i{b}
  // 1100 0100 000d dddd aaaa accc c1ii iiii  mulhd%s{c}.ss r%i{d}, r%i{a}, #%d{i}
  // 1100 0100 001d dddd aaaa accc c1ii iiii  mulhd%s{c}.su r%i{d}, r%i{a}, #%d{i}
  // 1100 0100 010d dddd aaaa accc c1ii iiii  mulhd%s{c}.us r%i{d}, r%i{a}, #%d{i}
  // 1100 0100 011d dddd aaaa accc c1ii iiii  mulhd%s{c}.uu r%i{d}, r%i{a}, #%d{i}
  // 1100 0100 100d dddd aaaa accc c00b bbbb  div%s{c}.ss r%i{d}, r%i{a}, r%i{b}
  // 1100 0100 101d dddd aaaa accc c00b bbbb  div%s{c}.su r%i{d}, r%i{a}, r%i{b}
  // 1100 0100 110d dddd aaaa accc c00b bbbb  div%s{c}.us r%i{d}, r%i{a}, r%i{b}
  // 1100 0100 111d dddd aaaa accc c00b bbbb  div%s{c}.uu r%i{d}, r%i{a}, r%i{b}
  // 1100 0100 100d dddd aaaa accc c1ii iiii  div%s{c}.ss r%i{d}, r%i{a}, #%d{i}
  // 1100 0100 101d dddd aaaa accc c1ii iiii  div%s{c}.su r%i{d}, r%i{a}, #%d{i}
  // 1100 0100 110d dddd aaaa accc c1ii iiii  div%s{c}.us r%i{d}, r%i{a}, #%d{i}
  // 1100 0100 111d dddd aaaa accc c1ii iiii  div%s{c}.uu r%i{d}, r%i{a}, #%d{i}
  // 1100 0101 000d dddd aaaa accc c00b bbbb  adds%s{c} r%i{d}, r%i{a}, r%i{b}
  // 1100 0101 000d dddd aaaa accc c1ii iiii  adds%s{c} r%i{d}, r%i{a}, #%d{i}
  // 1100 0101 001d dddd aaaa accc c00b bbbb  subs%s{c} r%i{d}, r%i{a}, r%i{b}
  // 1100 0101 001d dddd aaaa accc c1ii iiii  subs%s{c} r%i{d}, r%i{a}, #%d{i}
  // 1100 0101 010d dddd aaaa accc c00b bbbb  lsls%s{c} r%i{d}, r%i{a}, r%i{b}
  // 1100 0101 010d dddd aaaa accc c1ii iiii  lsls%s{c} r%i{d}, r%i{a}, #%d{i}
  // 1100 0101 011d dddd aaaa accc c00b bbbb  clamp16%s{c} r%i{d}, r%i{a}, r%i{b}
  // 1100 0101 011d dddd aaaa accc c1ii iiii  clamp16%s{c} r%i{d}, r%i{a}, #%d{i}
  // 1100 0101 1xxd dddd aaaa accc c00b bbbb  addscale%s{c} r%i{d}, r%i{a}, r%i{b} lsl %d{x+5}
  // 1100 0101 1xxd dddd aaaa accc c1ii iiii  addscale%s{c} r%i{d}, r%i{a}, #%d{i} lsl %d{x+5}
  // 1100 0110 000d dddd aaaa accc c00b bbbb  count%s{c} r%i{d}, r%i{a}, r%i{b}
  // 1100 0110 000d dddd aaaa accc c1ii iiii  count%s{c} r%i{d}, r%i{a}, #%d{b}
  // 1100 0110 xxxd dddd aaaa accc c00b bbbb  subscale%s{c} r%i{d}, r%i{a}, r%i{b} lsl %d{x}
  // 1100 0110 xxxd dddd aaaa accc c1ii iiii  subscale%s{c} r%i{d}, r%i{a}, #%d{i} lsl %d{x}
  // 1100 0111 000d dddd aaaa accc c00b bbbb  subscale%s{c} r%i{d}, r%i{a}, r%i{b} lsl 8
  // 1100 0111 000d dddd aaaa accc c1ii iiii  subscale%s{c} r%i{d}, r%i{a}, #%d{i} lsl 8

  // 1100 0111 xxxx xxxx xxxx xxxx xxxx xxxx  exception 3
  // 1100 0111 001x xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xC720, 0x0000);
  // 1100 0111 010x xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xC740, 0x0000);
  // 1100 0111 011x xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xC760, 0x0000);
  // 1100 0111 100x xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xC780, 0x0000);
  // 1100 0111 101x xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xC7a0, 0x0000);
  // 1100 0111 110x xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xC7d0, 0x0000);
  // 1100 0111 111x xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xC7e0, 0x0000);

  // 1100 100f fffd dddd aaaa accc c00b bbbb  %s{f}%s{c} r%i{d}, r%i{a}, r%i{b}
  // 1100 100f fffd dddd aaaa accc c1ii iiii  %s{f}%s{c} r%i{d}, r%i{a}, #%i{i}
  // 1100 1010 000d dddd aaaa accc c00b bbbb  ftrunc%s{c} r%i{d}, r%i{a}, sasl r%i{b}
  // 1100 1010 000d dddd aaaa accc c100 0000  ftrunc%s{c} r%i{d}, r%i{a}
  // 1100 1010 000d dddd aaaa accc c1ii iiii  ftrunc%s{c} r%i{d}, r%i{a}, sasl #%i{i}
  // 1100 1010 001d dddd aaaa accc c00b bbbb  floor%s{c} r%i{d}, r%i{a}, sasl r%i{b}
  // 1100 1010 001d dddd aaaa accc c100 0000  floor%s{c} r%i{d}, r%i{a}
  // 1100 1010 001d dddd aaaa accc c1ii iiii  floor%s{c} r%i{d}, r%i{a}, sasl #%i{i}
  // 1100 1010 010d dddd aaaa accc c00b bbbb  flts%s{c} r%i{d}, r%i{a}, sasr r%i{b}
  // 1100 1010 010d dddd aaaa accc c100 0000  flts%s{c} r%i{d}, r%i{a}
  // 1100 1010 010d dddd aaaa accc c1ii iiii  flts%s{c} r%i{d}, r%i{a}, sasr #%i{i}
  // 1100 1010 011d dddd aaaa accc c10b bbbb  fltu%s{c} r%i{d}, r%i{a}, sasr r%i{b}
  // 1100 1010 011d dddd aaaa accc c100 0000  fltu%s{c} r%i{d}, r%i{a}
  // 1100 1010 011d dddd aaaa accc c1ii iiii  fltu%s{c} r%i{d}, r%i{a}, sasr #%i{i}

  // 1100 1010 1xxx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xCA80, 0x0000);
  // 1100 1011 xxxx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xCB00, 0x0000);

  // 1100 1100 000d dddd 0000 0000 000a aaaa  mov p_reg%d{d}, r%d{a}
  // 1100 1100 001d dddd 0000 0000 000a aaaa  mov r%d{d}, p_reg%d{a}

  // 1100 1100 00xx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xCC00, 0x8000);
  // 1100 1100 01xx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xCC40, 0x0000);
  // 1100 1100 1xxx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xCC80, 0x0000);
  // 1100 1101 xxxx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xCD00, 0x0000);
  // 1100 1110 xxxx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xCE00, 0x0000);
  // 1100 1111 xxxx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xCF00, 0x0000);
  // 1101 xxxx xxxx xxxx xxxx xxxx xxxx xxxx  exception 3
  TEST2(0xD000, 0x0000);


  //
  // Now test illegal 48 bit instructions
  //

  // 1110 0000 0000 0000 uuuu uuuu uuuu uuuu uuuu uuuu uuuu uuuu  j 0x%08x{u}
  // 1110 0001 0000 0000 oooo oooo oooo oooo oooo oooo oooo oooo  b 0x%08x{$+o}
  // 1110 0010 0000 0000 uuuu uuuu uuuu uuuu uuuu uuuu uuuu uuuu  jl 0x%08x{u}
  // 1110 0011 0000 0000 oooo oooo oooo oooo oooo oooo oooo oooo  bl 0x%08x{$+o}
  // 1110 00xx xxxx xxxx yyyy yyyy yyyy yyyy yyyy yyyy yyyy yyyy  unknown_0x%04x{0xe000+x}%08x{y}

  // 1110 0100 xxxx xxxx yyyy yyyy yyyy yyyy yyyy yyyy yyyy yyyy  exception 3
  TEST3(0xE400, 0x0000, 0x0000);

  // 1110 0101 000d dddd oooo oooo oooo oooo oooo oooo oooo oooo  lea r%i{d}, 0x%08x{$+o} ;(pc)

  // 1110 0101 xxxx xxxx yyyy yyyy yyyy yyyy yyyy yyyy yyyy yyyy  exception 3
  TEST3(0xE520, 0x0000, 0x0000);
  TEST3(0xE540, 0x0000, 0x0000);
  TEST3(0xE560, 0x0000, 0x0000);
  TEST3(0xE580, 0x0000, 0x0000);
  TEST3(0xE5A0, 0x0000, 0x0000);
  TEST3(0xE5C0, 0x0000, 0x0000);
  TEST3(0xE5E0, 0x0000, 0x0000);

  // 1110 0110 ww0d dddd ssss sooo oooo oooo oooo oooo oooo oooo  ld%s{w} r%i{d}, 0x%08x{o}(r%i{s})
  // 1110 0110 ww1d dddd ssss sooo oooo oooo oooo oooo oooo oooo  st%s{w} r%i{d}, 0x%08x{o}(r%i{s})
  // 1110 0111 ww0d dddd 1111 1ooo oooo oooo oooo oooo oooo oooo  ld%s{w} r%i{d}, 0x%08x{$+o} ;(pc)
  // 1110 0111 ww1d dddd 1111 1ooo oooo oooo oooo oooo oooo oooo  st%s{w} r%i{d}, 0x%08x{$+o} ;(pc)

  // 1110 0111 xxxx xxxx yyyy yyyy yyyy yyyy yyyy yyyy yyyy yyyy  exception 3

  //  movi(r0, 0x80000000);
  TEST3(0xE700, 0x0000, 0x0000);

  // 1110 10pp pppd dddd uuuu uuuu uuuu uuuu uuuu uuuu uuuu uuuu  %s{p} r%i{d}, #0x%08x{u}
  // 1110 11ss sssd dddd uuuu uuuu uuuu uuuu uuuu uuuu uuuu uuuu  add r%i{d}, r%i{s}, #0x%08x{u}


  movi(r0, ('D'<<0)|('O'<<8)|('N'<<16)|('E'<<24));
  bl(uart_putchars);

  bra(led_flash);


//
// Led flasher
//

label(led_flash);

    movi(r10, 0x7e200000);
    movi(r4,  0x00040000);
    movi(r11, 0x00010000);
    
    movi(r3, GPFSEL1);
    movi(r1, ~(7<<18));
    movi(r2, (1<<18));
    ld(r0, r3);
    andi(r0, ~(7<<18));
    ori(r0, (1<<18));
    st(r0, r3);

declare(led_flash_loop);
label(led_flash_loop);
    st_off(r11, 0x1c, r10);

    movi(r4, 0);
declare(led_flash_delay1);
label(led_flash_delay1);
    addi(r4, 1);
    cmpi(r4, 0x00100000);
    bne(led_flash_delay1);
    st_off(r11, 0x28, r10);

    movi(r4, 0);
declare(led_flash_delay2);
label(led_flash_delay2);
    addi(r4, 1);
    cmpi(r4, 0x00100000);
    bne(led_flash_delay2);

    bra(led_flash_loop);


//
// UART
//

label(uart_init);

  // Configure TX and RX GPIO pins for Mini Uart function.
  movi(r1, GPFSEL1);
  ld(r0, r1);
  andi(r0, ~(7<<12));
  ori(r0, (2)<<12);
  andi(r0, ~(7<<15));
  ori(r0, 2<<15);
  st(r0, r1);

  movi(r1, GPPUD);
  movi(r0, 0);
  st(r0, r1);

  movi(r0, 0);

declare(delay1);
label(delay1);
  nop();
  addi(r0, 1);
  cmpi(r0, 150);
  bne(delay1);
  movi(r1, GPPUDCLK0);
  movi(r0, (1<<14)|(1<<15));
  st(r0, r1);

  movi(r0, 0);
declare(delay2);
label(delay2);
  nop();
  addi(r0, 1);
  cmpi(r0, 150);
  bne(delay2);
  movi(r1, GPPUDCLK0);
  movi(r0, 0);
  st(r0, r1);

  // Set up serial port
  movi(r1, AUX_ENABLES); movi(r0, 1); st(r0, r1);

  movi(r1, AUX_MU_IER_REG); movi(r0, 0); st(r0, r1);
  movi(r1, AUX_MU_CNTL_REG); movi(r0, 0); st(r0, r1);
  movi(r1, AUX_MU_LCR_REG); movi(r0, 3); st(r0, r1);
  movi(r1, AUX_MU_MCR_REG); movi(r0, 0); st(r0, r1);
  movi(r1, AUX_MU_IER_REG); movi(r0, 0); st(r0, r1);
  movi(r1, AUX_MU_IIR_REG); movi(r0, 0xC6); st(r0, r1);
  movi(r1, AUX_MU_BAUD_REG); movi(r0, ((SYSTEM_CLOCK/(TARGET_BAUD_RATE*8))-1)); st(r0, r1);
  movi(r1, AUX_MU_LCR_REG); movi(r0, 0x03); st(r0, r1);
  movi(r1, AUX_MU_CNTL_REG); movi(r0, 3); st(r0, r1);
  rts();

label(uart_putcrlf);
  movi(r0, 0x0a0d);
label(uart_putchars);
  movi(r1, AUX_MU_LSR_REG);
  ld(r1, r1);
  btsti(r1, 5);
  beq(uart_putchars);
  movi(r1, AUX_MU_IO_REG);
  st(r0, r1);
  lsri(r0, 8);
  cmpi(r0, 0);
  bne(uart_putchars);
  rts();

declare(digits);
declare(_uart_puthexword_loop);
declare(_uart_puthexword_uart_putchars);

label(uart_puthexword);
  movi(r3, 0);

label(_uart_puthexword_loop);
  mov(r1, r0);
  lsri(r1, 28);
  lea(r2, digits);
  add(r2, r1);
  ldb(r2, r2);
label(_uart_puthexword_uart_putchars);
  movi(r1, AUX_MU_LSR_REG);
  ld(r1, r1);
  btsti(r1, 5);
  beq(_uart_puthexword_uart_putchars);
  movi(r1, AUX_MU_IO_REG);
  st(r2, r1);
  lsli(r0, 4);
  addcmpb_c_rd_i_u_o8(c_ne, r3, 1, 8, pcrel(_uart_puthexword_loop)/2);
  rts(); 

label(digits);
  string("0123456789abcdef");

  align(2);


//
// Exception Handlers
//
// Generate a report of the form:
//
// EXC <exception_number> <sp> <pc> <sr>
// REG <r0> <r1> ... <r23>
//

  // Forward declaration of true exception handler
  declare(exception);

  // Make 128 exception handlers that load the exception number
  // and jump to the real exception handler

  for(int i=0; i<0x80; i++) {
  //
label(exceptions[i]);
  push_rb_rnb(0,24);
  movi(r0, i);
  b(exception);
  //
  }

label(exception);

  // Stack from high address to low:
  // sr, pc, r0, r1, ... r23 
  //                     ^
  //                     |-- sp points here

  // Save exception number
  mov(r4, r0);

  bl(uart_putcrlf);

  // Print "EXC "
  movi(r0, 'E'<<0|'X'<<8|'C'<<16|' '<<24); bl(uart_putchars);

  // Print <exception number>
  mov(r0, r4); bl(uart_puthexword);

  // Print <sp>
  lea_rd_o_rs(r23, 24*4+2*4, r25);
  movi(r0, ' '); bl(uart_putchars); mov(r0, r23); bl(uart_puthexword);
  addi(r23, 4);

  // Print <pc> <sr>
  movi(r4, 2);
declare(exception_loop);
label(exception_loop);
  movi(r0, ' '); bl(uart_putchars); ld_rd_dec_rs(r0, r23); bl(uart_puthexword);
  addcmpb_c_rd_i_u_o8(c_ne, r4, -1, 0, pcrel(exception_loop)/2);

  // New line
  bl(uart_putcrlf);

  // Print "REG "
  movi(r0, 'R'<<0|'E'<<8|'G'<<16|' '<<24); bl(uart_putchars);

  // Dump saved regs <r0> <r1> ... <r23>
  movi(r4, 24);
declare(exception_loop2);
label(exception_loop2);
  ld_rd_dec_rs(r0, r23); bl(uart_puthexword);
  movi(r0, ' '); bl(uart_putchars);
  addcmpb_c_rd_i_u_o8(c_ne, r4, -1, 0, pcrel(exception_loop2)/2);

  // Exit exception back to the next instruction
  pop_rb_rnb(r0, 24);
  rti();

  END
