//-------------------------------------------------------------------------
// VideoCore IV implementation of dwelch67's blinker01 sample.
// See: https://github.com/dwelch67/raspberrypi/tree/master/blinker01)
//-------------------------------------------------------------------------
/*
        extern void PUT32 ( unsigned int, unsigned int );
        extern unsigned int GET32 ( unsigned int );
        extern void dummy ( unsigned int );

        #define GPFSEL4 0x20200010
        #define GPSET1  0x20200020
        #define GPCLR1  0x2020002c

        int notmain ( void )
        {
            unsigned int ra;

            ra=GET32(GPFSEL4);
            ra&=~(7<<21);
            ra|=1<<21;
            PUT32(GPFSEL4,ra);

            while(1)
            {
                PUT32(GPSET1,1<<15);
                for(ra=0;ra<0x100000;ra++) dummy(ra);
                PUT32(GPCLR1,1<<15);
                for(ra=0;ra<0x100000;ra++) dummy(ra);
            }
            return(0);
        }
*/

  START("blinker01.bin");

  equ(GPFSEL4, 0x7e200010);
  equ(GPSET1, 0x7e200020);
  equ(GPCLR1, 0x7e20002c);

  declare(loop);
  declare(delayloop1);
  declare(delayloop2);

  fillb(0x200, 0);

  movi(r1, GPFSEL4);
  ld(r0, r1);
  andi(r0, ~(7<<21));
  ori(r0, 1<<21);
  st(r0, r1);

  movi(r1, GPSET1);
  movi(r2, GPCLR1);
  movi(r3, 1<<15);

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
