
CROSS_COMPILE := x86_64-elf-
TOOLCHAIN_PATH := $(CURDIR)/../toolchain/gcc-x86_64-elf/bin
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)gcc
AS := $(CROSS_COMPILE)as
OBJCOPY := $(CROSS_COMPILE)objcopy
OBJDUMP := $(CROSS_COMPILE)objdump
CFLAGS := -O3

BASE_DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
BUILD_DIR=$(BASE_DIR)build/
H_FILES := $(shell find -name "*.h")
C_FILES := $(shell find -name "*.c")
AS_FILES := $(shell find -name "*.s")
O_FILES := $(patsubst %.s,%.o,$(AS_FILES)) $(patsubst %.c,%.o,$(C_FILES))
LD_SCRIPT := kernel.ld

export PATH := $(TOOLCHAIN_PATH):$(PATH)

$(BUILD_DIR)rom.img: $(BUILD_DIR)rom.elf | $(BUILD_DIR)
	$(OBJCOPY) -O binary $< $@

$(BUILD_DIR)rom.elf: $(LD_SCRIPT) $(O_FILES) | $(BUILD_DIR)
	$(LD) $(CFLAGS) -ffreestanding -nostdlib -T $(LD_SCRIPT) -o $@ $(O_FILES)

$(BUILD_DIR):
	mkdir $@

%.o: %.c $(H_FILES)
	$(CC) $(CFLAGS) -m64 -ffreestanding -fno-pic -mcmodel=kernel -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -nostdlib -lgcc -c $< -o $@

%.o: %.s $(H_FILES)
	$(AS) $< -o $@

clean:
	rm $(O_FILES)
	rm -rf $(BUILD_DIR)

show_asm: $(BUILD_DIR)rom.elf
	$(OBJDUMP) -D $<

.PHONY: show_asm
