.PHONY: all
all: pwnit.so

%.o: %.S
	gcc -c $(EXTRA_CFLAGS) $< -o $@

%.so: %.o
	objcopy -O binary $< $@

.PHONY: gdb
gdb: pwnit.so
	gdb \
		-ex "set env LD_LIBRARY_PATH=output" \
		-ex "set args <pwnit.so" \
		-ex "set breakpoint pending on" \
		-ex "b challenge" \
		-ex "r" \
		-ex "b *(challenge-0x23d50+0x24bc5)" \
		-ex "c" \
		output/blockchain

.PHONY: local
local: pwnit.so
	LD_LIBRARY_PATH=output output/blockchain <pwnit.so

.PHONY: clean
clean:
	rm -f pwnit.o pwnit.so
