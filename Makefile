# Find all target directories
TARGET_DIRS := $(wildcard builds/target_*b)

# Find all .circom files in those directories
CIRCOM_FILES := $(wildcard $(addsuffix /*_*b.circom,$(TARGET_DIRS)))

# Extract target sizes (e.g., "512b", "1024b") from directory names
TARGET_SIZES := $(patsubst builds/target_%,%,$(TARGET_DIRS))

# Create artifacts directories
$(shell mkdir -p $(addsuffix /artifacts,$(TARGET_DIRS)))

# Default target
.PHONY: all clean
all: build params

# Build target
.PHONY: build
build:
	@set -e;
	@for circuit in $(CIRCOM_FILES); do \
		echo "Processing $${circuit}..."; \
		circom "$${circuit}" --r1cs --wasm --O1 -o "$$(dirname $${circuit})/artifacts" -l node_modules; \
		build-circuit "$${circuit}" "$$(dirname $${circuit})/artifacts/$$(basename $${circuit} .circom).bin" -l node_modules; \
		echo "====================xxxxxxxxxx===================="; \
	done

# Parameters target
.PHONY: params
params:
	@for target_dir in $(TARGET_DIRS); do \
		size=$$(basename "$$target_dir" | sed 's/target_//' | sed 's/b//'); \
		rom_length=$$(echo "$$size / 16 + 16" | bc); \
		echo "Generating parameters for $${size}b with ROM length $$rom_length..."; \
		cargo +nightly run --release -- "$$target_dir/artifacts" "$${size}b" "$$rom_length" || exit 1; \
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
	@echo "\nFound target sizes:"
	@echo $(TARGET_SIZES)
	@echo "\nArtifacts will be generated in:"
	@echo $(addsuffix /artifacts,$(TARGET_DIRS))