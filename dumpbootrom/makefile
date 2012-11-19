all:	dumpbootrom dump2bin
	
dumpbootrom: dumpbootrom.s build.c ../tinyasm/asm.c
	gcc build.c -o build
	./build

dump2bin: dump2bin.c
	gcc dump2bin.c -o dump2bin

clean:
	rm dumpbootrom.bin
