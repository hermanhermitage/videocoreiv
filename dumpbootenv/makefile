dumpbootenv.bin: dumpbootenv.s build.c ../tinyasm/asm.c
	$(CC) --std=c99 build.c -o build
	./build

clean:
	rm -f dumpbootenv.bin
