# If O= is specified, that's the output directory
ifdef O
  BUILD_OUTPUT := $(O)
else
  BUILD_OUTPUT := .
endif

# Use musl-gcc for static linking
CC = musl-gcc
CFLAGS = -Wall -Wextra -O2 -static $(EXTRA_CFLAGS)
LDFLAGS = -s $(EXTRA_LDFLAGS)

.PHONY: all clean

all: $(BUILD_OUTPUT)/deactivate

$(BUILD_OUTPUT)/deactivate: deactivate.c
	@mkdir -p $(BUILD_OUTPUT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(BUILD_OUTPUT)/deactivate 