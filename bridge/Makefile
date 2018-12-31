
BASE_DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
BUILD_DIR=$(BASE_DIR)build/

H_FILES := $(shell find -name "*.h")
C_FILES := $(shell find -name "*.c")
O_FILES := $(patsubst %.s,%.o,$(AS_FILES)) $(patsubst %.c,%.o,$(C_FILES))
CFLAGS := -g

$(BUILD_DIR)bridge: $(O_FILES) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(O_FILES)

$(BUILD_DIR):
	mkdir $@

%.o: %.c $(H_FILES)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(O_FILES)
	rm -rf $(BUILD_DIR)
