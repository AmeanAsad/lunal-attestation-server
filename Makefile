# Makefile
.PHONY: all clean ffi ffi-custom install

# Default target
all: ffi

# Directory configuration
BUILD_DIR = build
SRC_DIR = pkg/attestation

# The output shared library
LIB_NAME = libattestation.so
LIB_PATH = $(BUILD_DIR)/$(LIB_NAME)

# Build the FFI shared library
ffi: | $(BUILD_DIR)
	CGO_ENABLED=1 go build -buildmode=c-shared -o $(LIB_PATH) ./cmd/ffi/main.go
	@echo "FFI library built successfully: $(LIB_PATH)"

# Build the FFI shared library with a custom build directory
# Usage: make ffi-custom CUSTOM_BUILD_DIR=path/to/directory
ffi-custom:
	@if [ -z "$(CUSTOM_BUILD_DIR)" ]; then \
		echo "Error: CUSTOM_BUILD_DIR parameter is required"; \
		echo "Usage: make ffi-custom CUSTOM_BUILD_DIR=path/to/directory"; \
		exit 1; \
	fi
	mkdir -p $(CUSTOM_BUILD_DIR)
	CGO_ENABLED=1 go build -buildmode=c-shared -o $(CUSTOM_BUILD_DIR)/$(LIB_NAME) ./cmd/ffi/main.go
	@echo "FFI library built successfully: $(CUSTOM_BUILD_DIR)/$(LIB_NAME)"

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts"

# Install the library to system location (may require sudo)
install: ffi
	install -m 0644 $(LIB_PATH) /usr/local/lib/
	install -m 0644 $(BUILD_DIR)/$(LIB_NAME:.so=.h) /usr/local/include/
	ldconfig
	@echo "Library installed to /usr/local/lib/ and /usr/local/include/"