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
Documentation and samples on the VideoCore IV instruction set as used in the BCM SoC used in the Raspberry Pi.

For more information on the Raspberry Pi, see the foundation's site at http://raspberrypi.org,
or the embedded linux wiki at http://elinux.org/R-Pi_Hub.

Active discussions take place on IRC (freenode) on #raspberrypi-internals, #raspberrypi-osdev, #raspberrypi-dev, 
and #raspberrypi.

We are in a very early stage of understanding of the device.  At this stage we only have Serial IO and GPIO for
flashing things like the status led.  You will need to attach a terminal to the Mini UART on the GPIO connector.
For more details see "Getting started" below.

Documentation:
==
1. Getting started: https://github.com/hermanhermitage/videocoreiv/wiki/Getting-Started
2. Instruction set: https://github.com/hermanhermitage/videocoreiv/wiki/VideoCore-IV-Programmers-Manual

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
3. Patent Applications on Broadcom SoC Method and Systems
  * [US20060184987](http://www.google.com/patents/US20060184987)  Intelligent Dma in a Mobile Multimedia Processor Supporting Multiple Display Formats
  * [US20080291208](http://www.google.com/patents/US20080291208)	Method and System for Processing Data Via a 3d Pipeline Coupled to a Generic Video Processing Unit
  * [US20080292216](http://www.google.com/patents/US20080292216)	Method and System for Processing Images using Variable Sized Tiles
  * [US20080292219](http://www.google.com/patents/US20080292219)	Method and System for an Image Sensor Pipeline on a Mobile Imaging Device
  * [US20090232347](http://www.google.com/patents/US20090232347)	Method and System for Inserting Software Processing In a Hardware Image Sensor Pipeline
  * [US20110148901](http://www.google.com/patents/US20110148901)	Method and System for Tile Mode Renderer With Coordinate Shader
  * [US20110154307](http://www.google.com/patents/US20110154307)	Method and System for Utilizing Data Flow Graphs to Compile Shaders
  * [US20110154377](http://www.google.com/patents/US20110154377)	Method and System for Reducing Communication During Video Processing Utilizing Merge Buffering
  * [US20110216069](http://www.google.com/patents/US20110216069)	Method and System for Compressing Tile Lists Used for 3d Rendering
  * [US20110221743](http://www.google.com/patents/US20110221743)	Method and System for Controlling a 3d Processor Using a Control List in Memory
  * [US20110227920](http://www.google.com/patents/US20110227920)	Method and System for a Shader Processor With Closely Couple Peripherals
  * [US20110242113](http://www.google.com/patents/US20110242113)	Method and System for Processing Pixels Utilizing Scoreboarding
  * [US20110242344](http://www.google.com/patents/US20110242344)	Method and System for Determining How to Handle Processing of an Image Based Motion
  * [US20110242427](http://www.google.com/patents/US20110242427)	Method and System for Providing 1080P Video with 32 Bit Mobile DDR Memory
  * [US20110249744](http://www.google.com/patents/US20110249744)	Method and System for Video Processing Utilizing Scalar Cores and a Single Vector Core
  * [US20110254995](http://www.google.com/patents/US20110254995)	Method and System for Mitigating Seesawing Effect During Autofocus
  * [US20110261059](http://www.google.com/patents/US20110261059)	Method and System for Decomposing Complex Shapes Into Curvy RHTS For Rasterization
  * [US20110261061](http://www.google.com/patents/US20110261061)	Method and System for Processing Image Data on a Per Tile Basis in an Image Sensor Pipeline
  * [US20110279702](http://www.google.com/patents/US20110279702)	Method and System for Providing A Programmable and Flexible Image Sensor Pipeline For Multiple Input Patterns
4. Patents on the baseline Alphamosaic processor
  * [US7028143](http://www.google.com/patents/US7028143)  Narrow/Wide Cache
  * [US7036001](http://www.google.com/patents/US7036001)	Vector Processing System
  * [US7457941](http://www.google.com/patents/US7457941)	Vector Processing System
  * [US7043618](http://www.google.com/patents/US7043618)	System for Memory Access in a Data Processor
  * [US7107429](http://www.google.com/patents/US7107429)	Data Access in a Processor
  * [US7069417](http://www.google.com/patents/US7069417)	Vector Processing System, 
  * [US7818540](http://www.google.com/patents/US7818540)	Vector Processing System
  * [US7080216](http://www.google.com/patents/US7080216)	Data Access in a Processor
  * [US7130985](http://www.google.com/patents/US7130985)	Parallel Processor Executing an Instruction Specifying Any Location First Operand Register and Group Configuration in Two Dimensional Register File
  * [US7167972](http://www.google.com/patents/US7167972)	Vector/Scalar System With Vector Unit Producing Scalar Result from Vector Results According to Modifier in Vector Instruction
  * [US7350057](http://www.google.com/patents/US7350057)	Scalar Result Producing Method in Vector/Scalar System by Vector Unit from Vector Results According to Modifier in Vector Instruction
  * [US7200724](http://www.google.com/patents/US7200724)	Two Dimentional Access in a Data Processor
  * [US7203800](http://www.google.com/patents/US7203800)	Narrow/Wide Cache
5. Patents Applications on the baseline Alphamosaic processor:
  * [US20030154361](http://www.google.com/patents/US20030154361) Instruction Execution in a Processor
  * [US20030159016](http://www.google.com/patents/US20030159016)	Data Access in a Processor
  * [US20030159017](http://www.google.com/patents/US20030159017)	Data Access in a Processor
  * [US20030159023](http://www.google.com/patents/US20030159023)	Repeated Instruction Execution
  * [US20030163667](http://www.google.com/patents/US20030163667)	Vector Processing System
  * [US20030159023](http://www.google.com/patents/US20030159023)	Application Registers
  * [US20040015682](http://www.google.com/patents/US20040015682)	Application Registers
  * [US20040019747](http://www.google.com/patents/US20040019747)	Narrow/Wide Cache
  * [US20040088521](http://www.google.com/patents/US20040088521)	Vector Processing System
  * [US20070061550](http://www.google.com/patents/US20070061550)	Instruction Execution in a Processor
  * [EP1320029](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=EP&NR=1320029A2&FT=D) Data processor with vector register file
  * [GB2382675](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=GB&NR=2382675A&FT=D)	Data access in a processor
  * [GB2382676](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=EP&NR=2382676A&FT=D)	Data access in a processor
  * [GB2382677](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=EP&NR=2382677A&FT=D)	Data access in a processor bitlines
  * [GB2382706](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=EP&NR=2382706A&FT=D)	Two dimensional memory structure with diagonal
  * [GB2382886](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=EP&NR=2382886A&FT=D)	Vector processing system
  * [GB2382887](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=EP&NR=2382887A&FT=D)	Instruction execution in a processor
  * [GB2383145](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=EP&NR=2383145A&FT=D)	Data access in a processor using a memory array accessed by coordinate instructions
  * [GB2390443](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=EP&NR=2390443A&FT=D)	A processor where some registers are not available to compiler generated code

  