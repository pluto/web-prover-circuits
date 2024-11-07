# Find all target directories
TARGET_DIRS := $(wildcard builds/target_*b)

# Find all .circom files in those directories
CIRCOM_FILES := $(wildcard $(addsuffix /*_*b.circom,$(TARGET_DIRS)))

# Create artifacts directories
$(shell mkdir -p $(addsuffix /artifacts,$(TARGET_DIRS)))

# Default target
.PHONY: all clean
all: build

# Build target
.PHONY: build
build:
	@for circuit in $(CIRCOM_FILES); do \
		echo "Processing $${circuit}..."; \
		circom "$${circuit}" --r1cs --wasm -o "$$(dirname $${circuit})/artifacts" -l node_modules; \
		build-circuit "$${circuit}" "$$(dirname $${circuit})/artifacts/$$(basename $${circuit} .circom).bin" -l node_modules; \
	done

# Clean target
clean:
	rm -rf $(addsuffix /artifacts,$(TARGET_DIRS))

# Debug target to show what files were found
.PHONY: debug
debug:
	@echo "Found directories:"
	@echo $(TARGET_DIRS)
	@echo "\nFound circom files:"
	@echo $(CIRCOM_FILES)
	@echo "\nArtifacts will be generated in:"
	@echo $(addsuffix /artifacts,$(TARGET_DIRS))