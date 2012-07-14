//-------------------------------------------------------------------------
// VideoCore IV implementation of dwelch67's blinker01 sample.
// See: https://github.com/dwelch67/raspberrypi/tree/master/blinker01)
//-------------------------------------------------------------------------
/*
				extern void PUT32 ( unsigned int, unsigned int );
				extern unsigned int GET32 ( unsigned int );
				extern void dummy ( unsigned int );

				#define GPFSEL1 0x20200004
				#define GPSET0  0x2020001C
				#define GPCLR0  0x20200028

				int notmain ( void )
				{
						unsigned int ra;

						ra=GET32(GPFSEL1);
						ra&=~(7<<18);
						ra|=1<<18;
						PUT32(GPFSEL1,ra);

						while(1)
						{
								PUT32(GPSET0,1<<16);
								for(ra=0;ra<0x100000;ra++) dummy(ra);
								PUT32(GPCLR0,1<<16);
								for(ra=0;ra<0x100000;ra++) dummy(ra);
						}
						return(0);
				}
*/

  START("blinker01.bin");

	equ(GPFSEL1, 0x7e200004);
	equ(GPSET0, 0x7e20001c);
	equ(GPCLR0, 0x7e200028);

	declare(loop);
	declare(delayloop1);
	declare(delayloop2);

	fillb(0x200, 0);

  movi(r1, GPFSEL1);
  ld(r0, r1);
  andi(r0, ~(7<<18));
  ori(r0, 1<<18);
  st(r0, r1);

  movi(r1, GPSET0);
  movi(r2, GPCLR0);
  movi(r3, 1<<16);

label(loop);
  st(r3, r1);

  movi(r0, 0);
label(delayloop1);
  addi(r0, 1);
	cmpi(r0, 0x100000);
  bne(delayloop1);
 
  st(r3, r2);

  movi(r0, 0);
label(delayloop2);
  addi(r0, 1);
  cmpi(r0, 0x100000);
  bne(delayloop2);

  bra(loop);

  END
