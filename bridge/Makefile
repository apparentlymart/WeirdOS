
BASE_DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
BUILD_DIR=$(BASE_DIR)build/

$(BUILD_DIR)bridge: | $(BUILD_DIR)
	touch $@

$(BUILD_DIR):
	mkdir $@

clean:
	rm -rf $(BUILD_DIR)
