CLANG ?= clang
CC ?= musl-gcc
CFLAGS := -O2 -Wall -Wextra -Werror $(EXTRA_CFLAGS)
LDFLAGS := $(EXTRA_LDFLAGS)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Support out-of-tree builds
ifeq ("$(origin O)", "command line")
  BUILD := $(O)
else
  BUILD := .
endif

BPF_CFLAGS := -target bpf \
    -D__TARGET_ARCH_$(ARCH) \
    -I$(BUILD) \
    -O2 -g \
    $(EXTRA_BPF_CFLAGS)

# Ensure build directory exists
$(shell mkdir -p $(BUILD))

all: $(BUILD)/execve_monitor

# Maintainer-only target to generate vmlinux.h
generate-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(BUILD)/%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/%.skel.h: $(BUILD)/%.bpf.o
	bpftool gen skeleton $< > $@

$(BUILD)/execve_monitor: execve_monitor.c $(BUILD)/execve_monitor.skel.h
	$(CC) $(CFLAGS) -I$(BUILD) $(LDFLAGS) -o $@ $< -lbpf
	strip -s $@

clean:
	rm -rf $(BUILD)/execve_monitor $(BUILD)/*.o $(BUILD)/*.skel.h

.PHONY: all clean generate-vmlinux 