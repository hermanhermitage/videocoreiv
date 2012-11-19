Here is a little sample GPU program that dumps the internal bootrom.  The bootrom is the code executed by the GPU on reset.
As usual, this information is provided for those interested in interoperability.  Neither the dump nor a disassembly are provided here as the original binary is subject to copyright.  Please use this tool responsibily and respect the rights of the owner.  In territories where DMCA or similar acts are in force you should avoid any circumvention activities.

# Installation:

It runs in place of bootcode.bin.  

1. Download dumpbootrom.bin
2. Rename it bootcode.bin
3. Rename your existing bootcode.bin on your SD card, say _bootcode.bin.
4. Copy the replacement bootcode.bin (dumpbootrom.bin) onto your SD card.
5. Boot up your Pi and use a terminal at 115200,n,8 to grab the hex dump.
6. Cut and paste the output into a tool to convert it to raw bytes (eg. dump2bin < bootrom.txt).
7. Subject to the territory you are in, you may which to disassemble it using http://hermanhermitage.github.com/videocore-disjs/dis.html

Note: It dumps the rom as little endian 32 bit words, and this may not be in the order you are expecting.  Eg:

As little endian 32 bit words:

  60000000: 00010203 04050607 08090a0b 0c0d0e0f
  ...

As bytes:

  60000000: 03 02 01 00 07 06 05 04 0b 0a 09 08 0f 0e 0d 0c
  ...

