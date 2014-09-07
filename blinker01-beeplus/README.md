Here is a little sample GPU program that flashes the OK or status light.

This version is the same as the one in blinker01 but designed to work with the Raspberry Pi Model B+, which has the ACT LED on a different GPIO pin.

# Installation:

It runs in place of bootcode.bin.  

Download the blinker01.bin here and replace the usual bootcode.bin file on
the SD card you use to boot your pi.  Don't forget to keep a backup of your old bootcode.bin so you can set it back to
normal operation!

Now when the GPU starts up, it looks for a program called bootcode.bin - so you'll have to rename blinker01.bin to bootcode.bin.

# How it works:

The boot routine in the GPU doesn't use the first 0x200 bytes as code, so we fill it with padding:

<pre>
00000000: 0000 0000 0000 0000: ..     :0000           ; zero bit instruction
00000002: 0000 0000 0000 0000: ..     :0000           ; zero bit instruction
...
000001fe: 0000 0000 0000 0000: ..     :0000           ; zero bit instruction
</pre>

Now we configure the GPIO so that the pin driving the status led is configured as an output signal by writing to GPFSEL1.
(see page 90 of http://www.raspberrypi.org/wp-content/uploads/2012/02/BCM2835-ARM-Peripherals.pdf).  Notice how the GPU
uses bus addresses starting at 0x7e000000.

<pre>
00000200: 1110 1000 0000 0001: .... ~ :e801 0004 7e20 ; mov r1, #0x7e200004
00000206: 0010 0000 0001 0000: .      :2010           ; ld  r0, 0x00(r1)
00000208: 1110 1000 1110 0000: ...... :e8e0 ffff ffe3 ; and r0, #0xffe3ffff
0000020e: 1110 1001 1010 0000: ...... :e9a0 0000 0004 ; or r0, r0, #0x00040000
00000214: 0011 0000 0001 0000: .0     :3010           ; st  r0, 0x00(r1)
</pre>

Set up some registers ready for the main loop:
<pre>
00000216: 1110 1000 0000 0001: .... ~ :e801 001c 7e20 ; mov r1, #0x7e20001c
0000021c: 1110 1000 0000 0010: ..(. ~ :e802 0028 7e20 ; mov r2, r0, #0x7e200028
00000222: 1110 1000 0000 0011: ...... :e803 0000 0001 ; mov r3, r0, #0x00010000
</pre>

Now lets begin the main loop.  First we turn the led off (or on depending on active high/low - I forget :) ) by writing to GPSET0 (0x7E20001C) to set the output high.

<pre>
00000228: 0011 0000 0001 0011: .0     :3013           ; st  r3, 0x00(r1)
</pre>

Loop to delay for a while:
<pre>
0000022a: 1110 1000 0000 0000: ...... :e800 0000 0000 ; mov r0, #0x00000000
00000230: 1110 1000 0100 0000: @..... :e840 0001 0000 ; add r0, r0, #0x00000001
00000236: 1110 1001 0100 0000: @..... :e940 0000 0010 ; cmp r0, r0, #0x00100000
0000023c: 0001 1000 1111 1010: ..     :18fa           ; bne 0x00000230
</pre>

Turn the led on (or off depending on active high/low - I forget :) ) by writing to GPCLR0 (0x7e200028) to clear the output low.
<pre>
0000023e: 0011 0000 0010 0011: #0     :3023           ; st  r3, 0x00(r2)
</pre>

Loop to delay for a while:
<pre>
00000240: 1110 1000 0000 0000: ...... :e800 0000 0000 ; mov r0, #0x00000000
00000246: 1110 1000 0100 0000: @..... :e840 0001 0000 ; add r0, r0, #0x00000001
0000024c: 1110 1001 0100 0000: @..... :e940 0000 0010 ; cmp r0, r0, #0x00100000
00000252: 0001 1000 1111 1010: ..     :18fa           ; bne 0x00000246
</pre>

Loop back to do it all again:
<pre>
00000254: 0001 1111 0110 1010: j.     :1f6a           ; b 0x00000228
</pre>
