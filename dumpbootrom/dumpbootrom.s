//-------------------------------------------------------------------------
// VideoCore IV boot rom dumper for Raspberry Pi
//-------------------------------------------------------------------------
  START("dumpbootrom.bin");

  // Because of the low system clock rate, this baud rate might be inaccurate
  // So be careful with your serial/terminal, some adjustment may be necessary.
  equ(TARGET_BAUD_RATE, 115200);

  // System clock is running directly off the 19.2MHz crystal at initial reset
  equ(SYSTEM_CLOCK, 19200000);

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

  declare(putchar);
  declare(putspace);
  declare(putcrlf);
  declare(hexdump);
  declare(print_hex);
  declare(init_uart);

  fillb(0x200, 0);

  bl(init_uart);

  movi(r0, 0x60000000);
  movi(r1, 0x60010000);
  bl(hexdump);

declare(loop);
label(loop);
  bra(loop);


label(init_uart);

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

label(hexdump);
// r0 = start address
// r1 = end address
  mov(r8, r0);
  mov(r9, r1);
  movs(r10, lr);

declare(memorydump_loop2);
label(memorydump_loop2);
  mov(r0, r8); bl(print_hex); movi(r0, ':'); bl(putchar); bl(putspace);
  ldq(r0, r8); addi(r8, 4); bl(print_hex); bl(putspace);
  ldq(r0, r8); addi(r8, 4); bl(print_hex); bl(putspace);
  ldq(r0, r8); addi(r8, 4); bl(print_hex); bl(putspace);
  ldq(r0, r8); addi(r8, 4); bl(print_hex); bl(putspace);
  bl(putcrlf);
  cmp(r8, r9);
  blo(memorydump_loop2);
  b_rd(r10);

label(putspace);
  movi(r0, 0x20);
  bra(putchar);
label(putcrlf);
  movi(r0, 0x0d);
  movi(r1, AUX_MU_LSR_REG);
  ld(r1, r1);
  btsti(r1, 5);
  beq(putcrlf);
  movi(r1, AUX_MU_IO_REG);
  st(r0, r1);
  movi(r0, 0x0a);
label(putchar);
  movi(r1, AUX_MU_LSR_REG);
  ld(r1, r1);
  btsti(r1, 5);
  beq(putchar);
  movi(r1, AUX_MU_IO_REG);
  st(r0, r1);
  rts();

declare(digits);
declare(_print_hex_loop);
declare(_print_hex_putchar);

label(print_hex);
  movi(r3, 0);

label(_print_hex_loop);
  mov(r1, r0);
  lsri(r1, 28);
  lea(r2, digits);
  add(r2, r1);
  ldb(r2, r2);
label(_print_hex_putchar);
  movi(r1, AUX_MU_LSR_REG);
  ld(r1, r1);
  btsti(r1, 5);
  beq(_print_hex_putchar);
  movi(r1, AUX_MU_IO_REG);
  st(r2, r1);
  lsli(r0, 4);
  addcmpb_c_rd_i_u_o8(c_ne, r3, 1, 8, pcrel(_print_hex_loop)/2);
  rts(); 

label(digits);
  string("0123456789abcdef");

  END
