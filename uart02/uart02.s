//-------------------------------------------------------------------------
// VideoCore IV implementation of dwelch67's uart01 sample.
// See: https://github.com/dwelch67/raspberrypi/tree/master/uart01)
//-------------------------------------------------------------------------

  START("uart02.bin");

  // Because of the low system clock rate, this baud rate might be inaccurate
  // So be careful with your serial/terminal, some adjustment may be necessary.
  equ(TARGET_BAUD_RATE, 115200);

  // System clock seems to be 20MHz at initial reset
  equ(SYSTEM_CLOCK, 19000000);

  equ(GPFSEL1, 0x7e200004);
  equ(GPSET0, 0x7e20001C);
  equ(GPCLR0, 0x7e200028);
  equ(GPPUD, 0x7e200094);
  equ(GPPUDCLK0, 0x7e200098);

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

  declare(hexstring);
  declare(digits);

  fillb(0x200, 0);

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

  movi(r0, 0x12345678);
  bl(hexstring);

declare(loop);
label(loop);
  // Wait char arrived in fifo
  movi(r1, AUX_MU_LSR_REG);
  ld(r0, r1);
  andi(r0, 0x1);
  cmpi(r0, 0x1);
  bne(loop);

  // Push next character into serial fifo
  movi(r1, AUX_MU_IO_REG);
  ld(r0, r1);
  st(r0, r1);
  bra(loop);

label(hexstring);
    movi(r3, 0);
declare(hexstring_loop);
label(hexstring_loop);
    mov(r1, r0);
    andi(r1, 0xf0000000);
    shri(r1, 28);
    lea(r2, digits);
    add(r2, r1);
    ldb(r2, r2);
declare(hexstring_putchar);
label(hexstring_putchar);
    movi(r1, AUX_MU_LSR_REG);
    ld(r1, r1); 
    andi(r1, 0x20);
    cmpi(r1, 0x20);
    bne(hexstring_putchar);
    movi(r1, AUX_MU_IO_REG);
    st(r2, r1);
    shli(r0, 4);
    addi(r3, 1);
    cmpi(r3, 8);
    bne(hexstring_loop);
    rts();   

label(digits);
    string("0123456789abcdef");

  END
