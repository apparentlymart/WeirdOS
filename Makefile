
BASE_DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
BUILD_DIR=$(BASE_DIR)build/

all: $(BUILD_DIR)weirdos-bridge $(BUILD_DIR)weirdos-rom.img

$(BUILD_DIR)weirdos-bridge: | $(BUILD_DIR)
	+$(MAKE) -C bridge
	cp bridge/build/bridge $@

$(BUILD_DIR)weirdos-rom.img: | toolchain $(BUILD_DIR)
	+$(MAKE) -C kernel
	cp kernel/build/rom.img $@

toolchain:
	+$(MAKE) -C toolchain

$(BUILD_DIR):
	mkdir $@

clean:
	rm -rf $(BUILD_DIR)
	+$(MAKE) -C bridge clean
	+$(MAKE) -C kernel clean

.PHONY: clean
