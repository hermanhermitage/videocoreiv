<pre>
Disclaimer:

This is a independent documentation project based on a combination of static analysis
and trial and error on real hardware.  This work is 100% independent from and not
sanctioned by or connected with Broadcom or its agents.

No Broadcom documents or materials were used beyond those publically available 
(see Referenced Materials).

This work was undertaken and the information provided for non commercial use on the 
expectation that hobbyists of all ages will find the details useful for understanding 
and working with their Raspberry Pi hardware.

The hope is that Broadcom will be flattered by the interest in the device and
understand the benefits of opening up understanding to a larger audience of 
potential customers and developers.

Broadcom should be commended with making their SoC available for a project as 
exciting as the Raspberry Pi.

The intent is that no copyrighted materials are contained in this repository.  
</pre>

Introduction
==

Purpose of this repo: Documentation and samples on the VideoCore IV instruction set as used in the BCM SoC used in the Raspberry Pi.  As of early 2016, Broadcom has yet to release public information on the VPU, so it is hoped you find this repo useful.

The BCM2835 SoC (System on a Chip) in the original RaspberryPi has the following significant computation units:
- **(ARM)** ARM1176JZF-S 700 MHz processor which acts as the "main" processor and typically runs Linux.
- **([VPU](https://github.com/hermanhermitage/videocoreiv))** Dualcore Videocore IV CPU @250MHz with SIMD Parallel Pixel Units (PPU) which runs scalar (integer and float) and vector (integer only) programs. Runs ThreadX OS, and generally coordinates all functional blocks such as video codecs, power management, video out.
- **(ISP)** Image Sensor Pipeline (ISP) providing lens shading, statistics and distortion correction.
- **([QPU](https://github.com/hermanhermitage/videocoreiv-qpu))** QPU units which provide 24 GFLOPS compute performance for coordinate, vertex and pixel shaders.  Whilst originally not documented, Broadcom released documentation and source code for the QPU in 2014.

Newer Raspberry Pi mix things up with faster and more modern ARM cores, but the VPU information here is still relevant.
 
For more information on the Raspberry Pi, see the foundation's site at http://raspberrypi.org,
or the embedded linux wiki at http://elinux.org/R-Pi_Hub.

Active discussions take place on IRC (freenode) on #raspberrypi-internals, #raspberrypi-osdev, #raspberrypi-dev, 
and #raspberrypi.

There is a raspberrypi-internals mailing list, you can subscribe at <a href="http://www.freelists.org/list/raspi-internals">mailing list page at
freelists.org</a>.

We are in a very early stage of understanding of the device.  At this stage we only have Serial IO and GPIO for
flashing things like the status led.  You will need to attach a terminal to the Mini UART on the GPIO connector.
For more details see "Getting started" below.  

It is now possibly to use VideoCore Kernels from Userland / Linux, 
see https://github.com/hermanhermitage/videocoreiv/wiki/VideoCore-IV-Kernels-under-Linux.  Our understanding of the
Videocore Processor is nearing completion, and it is an excellent target for integer SIMD and DSP kernels.  Essentially,
it can be used for 16 way SIMD processing of 8, 16 and 32 bit integer values.

#### Videocore IV Community and Resources:

I recommend starting with Julian's GNU toolchain, at https://github.com/itszor/vc4-toolchain

- **[2016-06-15]** SDRAM and ARM initialization reference code for the VPU is now available at https://github.com/christinaa/rpi-open-firmware 

- **[2016-05-03]** Kristina Brooks has got David Given's **LLVM fork** to work on rPi at https://github.com/christinaa/LLVM-VideoCore4

- **[2016-04-23]** Julian Brown has pulled together bits and pieces of previous **GNU toolchain** work and fixed them up so they work together at https://github.com/itszor/vc4-toolchain

- **[2015-11-08]** (QPU). Koichi NAKAMURA has developed a Python library for GPGPU on Raspberry Pi at https://github.com/nineties/py-videocore.

- **[2016-04-21]** (QPU). mn416 has developed QPULib, a programming language and compiler for the Raspberry Pi's Quad Processing Units at https://github.com/mn416/QPULib
 
- **[2015-01-02]** (QPU). A new QPU macro assembler from Marcel Müller. This builds on Pete and Eman’s earlier QPU assemblers to include support for macros and functions, at http://maazl.de/project/vc4asm/doc/index.html and https://github.com/maazl/vc4asm/

- **[2014-10-28]** (VPU). RPi foundation discusses how Argon Design use the VPU to accerate stereo depth perception at https://www.raspberrypi.org/blog/real-time-depth-perception-with-the-compute-module/ a comment about using MMAL is at https://www.raspberrypi.org/blog/real-time-depth-perception-with-the-compute-module/#comment-1078440

- **[2014-06-10]** (QPU). Louis Howe gives a talk on 'Hacking the Raspberry Pi's VideoCore IV GPU' at https://www.youtube.com/watch?v=eZd0IYJ7J40

- **[2014-06-09]** (QPU). Pete Warden wrote a series of posts covering Deep Learning, Optimizing for QPU, and Image Recognition at https://petewarden.com/2014/06/09/deep-learning-on-the-raspberry-pi/, https://petewarden.com/2014/08/07/how-to-optimize-raspberry-pi-code-using-its-gpu/ and https://petewarden.com/2015/05/10/image-recognition-on-the-raspberry-pi-2/.  He updated Eric's QPU assembler at https://github.com/jetpacapp/qpu-asm, and added QPU support to his DeepBeliefSDK at https://github.com/jetpacapp/DeepBeliefSDK/, and a QPU implementation of GEMM matrix-multiply at https://github.com/jetpacapp/pi-gemm

- **[2014-05-03]** (QPU). Eric Lorimer wrote a set of posts on Hacking The GPU For Fun And Profit (including SHA hashing) at https://rpiplayground.wordpress.com/2014/05/03/hacking-the-gpu-for-fun-and-profit-pt-1/, and wrote his own QPU assembler at https://github.com/elorimer/rpi-playground

- **[2014-02-28]** (QPU). Broadcom announced the release of full documentation for the VideoCore IV graphics core, and a complete source release of the graphics stack at https://www.raspberrypi.org/blog/a-birthday-present-from-broadcom/.  Note this does **NOT** include VPU documentation, except in so much that the source drop includes samples of VPU assembly.

- **[2014-01-30]** (QPU). Andrew Holme's QPU Fast Fourier Transform at http://www.aholme.co.uk/GPU_FFT/Main.htm.
 
- Volker Barthelmann has been adding Videocore IV to his tool chain and has a preliminary preview of his vasm assembler at http://www.ibaug.de/vasm/vasm.tar.gz, and vcc compiler at http://www.ibaug.de/vbcc/vbcc_vc4.tar.gz.

- David Given is adding Videocore IV support to ACK compiler & tool chain at http://tack.hg.sourceforge.net:8000/hgroot/tack/tack
in the dtrg-videocore branch.

- phire's https://github.com/phire/llvm repo contains some early work on porting llvm to videocore, and is ripe for
someone to grab and continue.  Phire has recently restarted work on this project.

- mm120's https://github.com/mm120/binutils-vc4/tree/vc4 repo is a work in progress adding videocore support to
gnu binutils.  It seems to be coming along nicely, and I will add some prebuilt binaries for Linux, OSX, Windows and
RPi/Linux to github soon.

- thubble's https://github.com/thubble/vcdevtools, https://github.com/thubble/videocore-elf-dis and 
https://github.com/thubble/binutils-vc4/tree/vc4 repos cover a videocore disassembler (C#), a preliminary assembler (C)
and a bootloader (asm) that can receive code via UART.  thubble is particularly focussed on documenting the instructions of
the integer vector processing unit (PPU).

- mgottschlag's https://github.com/mgottschlag/resim and https://github.com/mgottschlag/vctools repos are focussed
on tools and information for reverse engineering the bcm2835's hardware registers and functional blocks.  mgottschlag
is generating register access traces by simulating code sequencies on a remote computer running a videocore emulator and
forwarding them to a real bcm2835 running a small monitor.

- dwelch67's https://github.com/dwelch67/rpigpu repo is focussed on bare metal samples written in C.  dwelch67 has two
experimental binary translators targeting the videocore instruction set.  one translates mips to videocore and the
other translates arm thumb to videocore.

Documentation:
==
1. Getting started:    https://github.com/hermanhermitage/videocoreiv/wiki/Getting-Started
2. Instruction set:    https://github.com/hermanhermitage/videocoreiv/wiki/VideoCore-IV-Programmers-Manual
3. Hardware regs:      
  * https://github.com/hermanhermitage/videocoreiv/wiki/Register-Documentation and 
  * https://github.com/hermanhermitage/videocoreiv/wiki/MMIO-Register-map.
4. Kernels from Linux: https://github.com/hermanhermitage/videocoreiv/wiki/VideoCore-IV-Kernels-under-Linux
5. Performance Issues: https://github.com/hermanhermitage/videocoreiv/wiki/VideoCore-IV-Performance-Considerations
6. 3d Pipeline Overview:        https://github.com/hermanhermitage/videocoreiv/wiki/VideoCore-IV-3d-Graphics-Pipeline
7. QPU Shader Processors (24 GFLOPS):    https://github.com/hermanhermitage/videocoreiv-qpu

Methodology:
==
All information here has been obtained solely by a combination of:

1. Static analysis.
2. Experimentation on a Raspberry Pi.
3. Discussions on #raspberrypi-osdev and #raspberrypi-internals.

All activities were undertaken on a Raspberry Pi running Debian.

Those interested in the legal issues involved with reverse engineering activities, please review:

1. https://www.eff.org/issues/coders/reverse-engineering-faq
2. http://www.chillingeffects.org/reverse/faq.cgi
3. http://en.wikipedia.org/wiki/Reverse_engineering

We do not accept materials nor publish materials relating to DRM or its circumvention.

Referenced Materials
==
## Software and Binaries
### Official RasPi firmware and blobs
Available at https://github.com/raspberrypi/firmware/tree/master/boot.  Releases after May the 10th 2012 are
accompanied by a LICENSE.broadcom readme file containing copyright notice, a disclaimer and guidelines for use.
Prior to this date the readme was not present.

### Debian "Squeeze" Distribution
The distribution debian6-19-04-2012.zip from http://www.raspberrypi.org/downloads was used a development platform for
the majority of the work you find here.

## Data Sheets
2. BCM2835 ARM Peripherals data sheet at http://www.raspberrypi.org/wp-content/uploads/2012/02/BCM2835-ARM-Peripherals.pdf
3. VideoCore® IV 3D
 Architecture Reference Guide at https://docs.broadcom.com/docs/12358545

## Patents and Patent Applications

The original Alphamosaic patents and patent applications provide a wealth of information for understanding the
structure of the VideoCore instruction set and architecture.  Whilst the instruction encodings are different, and
only a limited range of instructions are indicated they prove an invaluable reference for understanding
the design space the engineers were exploring.

The newer Broadcom SoC patents and applications provide detailed information on how the VideoCore has been been
integrated into a broader platform setting.  They are invaluable for gaining a deeper insight into the additional
function units present in the BCM2835 and how they fit together.

### Patent Applications on Broadcom SoC Method and Systems
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
  * [US20110264902](http://www.google.com/patents/US20110264902)      Method and System For Suspending Video Processor and Saving Processor State in SDRAM Utilizing a Core Processor 
  * [US20110279702](http://www.google.com/patents/US20110279702)	Method and System for Providing A Programmable and Flexible Image Sensor Pipeline For Multiple Input Patterns

### Patents on the baseline Alphamosaic processor
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

### Patents Applications on the baseline Alphamosaic processor:
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
  * [GB2382676](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=GB&NR=2382676A&FT=D)	Data access in a processor
  * [GB2382677](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=GB&NR=2382677A&FT=D)	Data access in a processor bitlines
  * [GB2382706](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=GB&NR=2382706A&FT=D)	Two dimensional memory structure with diagonal
  * [GB2382886](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=GB&NR=2382886A&FT=D)	Vector processing system
  * [GB2382887](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=GB&NR=2382887A&FT=D)	Instruction execution in a processor
  * [GB2383145](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=GB&NR=2383145A&FT=D)	Data access in a processor using a memory array accessed by coordinate instructions
  * [GB2390443](http://worldwide.espacenet.com/publicationDetails/originalDocument?CC=GB&NR=2390443A&FT=D)	A processor where some registers are not available to compiler generated code

## Third Party Documents and Links

Some snippets of information appear in third party documents.

* [ARC Product Brochure - see screenshots showing registers/instructions](http://web.archive.org/web/20030915135553/http://www.arc.com/downloads/success_stories/C12260_Alphamosiac.pdf)
* [VideoCore 01 used for Automated Fingerprint Identification System - see powerpoint for sample of code.](http://itvsystems.com.ua/ru/soft/afis_mod.htm)
