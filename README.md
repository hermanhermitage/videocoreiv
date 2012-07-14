<pre>
Disclaimer:

This is a independent documentation project based on a combination of static analysis and trial and error on
real hardware.  This work is 100% independent from and not sanctioned by or connected with Broadcom or its agents.
No Broadcom documents or materials were used beyond those publically available (see Referenced Materials).

This work was undertaken and the information provided for non commercial use on the expectation that hobbyists of
all ages will find the details useful for understanding and working with their Raspberry Pi hardware.

The hope is that Broadcom will be flattered by the interest in the device and understand the benefits of opening up
understanding to a larger audience of potential customers and developers.

Broadcom should be commended with making their SoC available for a project as exciting as the Raspberry Pi.

No copyrighted materials are contained in this repository.  
</pre>

Introduction
==
Documentation on the VideoCore IV instruction set as used in the BCM SoC used in the Raspberry Pi.
This documentation is provided as-is in the hope it is useful to 

For more information on the Raspberry Pi, see the foundation's site at http://raspberrypi.org,
or the embedded linux wiki at http://elinux.org/R-Pi_Hub.

Active discussions take place on IRC (freenode) on #raspberrypi-internals, #raspberrypi-osdev, #raspberrypi-dev, 
and #raspberrypi.

Methodology:
==
All information here has been obtained solely by a combination of:

1. Static analysis.
2. Experimentation on a Raspberry Pi.
3. Discussions on #raspberrypi-osdev and #raspberrypi-internals.

All activities were undertaken on a Raspberry Pi running Debian.

Referenced Materials
==
1. Debian "Squeeze" Distribution debian6-19-04-2012.zip from http://www.raspberrypi.org/downloads.
2. BCM2835 ARM Peripherals data sheet at http://www.raspberrypi.org/wp-content/uploads/2012/02/BCM2835-ARM-Peripherals.pdf
