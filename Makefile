BPFTOOL ?= bpftool
CMAKE ?= cmake

BUILD_DIR := build
CMAKE_ARGS = -D CMAKE_BUILD_TYPE=Release
CMAKE_ARGS += -D CMAKE_C_COMPILER=clang -D CMAKE_CXX_COMPILER=clang++
CMAKE_ARGS += -D BPFTOOL=$(BPFTOOL)


.PHONY: all
all: $(BUILD_DIR)/Makefile
	$(MAKE) -C $(<D)

$(BUILD_DIR)/Makefile: CMakeLists.txt | $(BUILD_DIR)
	$(CMAKE) $(CMAKE_ARGS) -S $(<D) -B $(@D)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

.PHONY: clean
clean:
	rm -r $(BUILD_DIR)
