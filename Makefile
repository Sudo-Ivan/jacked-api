# Go compiler
GO := go

# Output directory
OUT_DIR := dist

# Examples to build (subdirectories in ./example)
EXAMPLES := basic http

# Get current system OS and ARCH for default builds
CURRENT_OS := $(shell $(GO) env GOOS)
CURRENT_ARCH := $(shell $(GO) env GOARCH)

# Target platforms for cross-compilation (OS/ARCH or OS/ARCH/ARM_VERSION)
TARGETS := linux/amd64 linux/arm64 linux/arm/v6

# Linker flags for release builds (strip symbols)
LDFLAGS_RELEASE := -ldflags="-s -w"

# --- Template for building one example for the current system ---
define BUILD_EXAMPLE_template
.PHONY: build-$(1)
build-$(1): $(OUT_DIR)/$(1)_$(CURRENT_OS)_$(CURRENT_ARCH)

$(OUT_DIR)/$(1)_$(CURRENT_OS)_$(CURRENT_ARCH): ./example/$(1)/main.go | $(OUT_DIR)
	@echo "Building $(1) for $(CURRENT_OS)/$(CURRENT_ARCH)..."
	@$(GO) build -o $$@ ./example/$(1)

endef

# --- Default Target: Build examples for current system ---
.PHONY: all build
all: build
build: $(addprefix build-, $(EXAMPLES))

# --- Generate build rules for current system using the template ---
$(foreach example,$(EXAMPLES),$(eval $(call BUILD_EXAMPLE_template,$(example))))

# --- Cross-compilation Targets ---
.PHONY: build-cross
build-cross: $(addprefix build-cross-, $(TARGETS))

# Generates targets like build-cross-linux/amd64, build-cross-linux/arm64, etc.
$(foreach target,$(TARGETS),$(eval build-cross-$(target): $(addprefix $(OUT_DIR)/, $(addsuffix _$(subst /,_,$(target)), $(EXAMPLES)))))
$(foreach target,$(TARGETS),$(eval .PHONY: build-cross-$(target)))

# Rule to build a specific example for a specific cross-compile target
# Example: make dist/basic_linux_amd64
$(OUT_DIR)/%_linux_amd64: ./example/%/main.go | $(OUT_DIR)
	@echo "Cross-compiling $(*) for linux/amd64..."
	@GOOS=linux GOARCH=amd64 $(GO) build -o $@ ./example/$(*)

$(OUT_DIR)/%_linux_arm64: ./example/%/main.go | $(OUT_DIR)
	@echo "Cross-compiling $(*) for linux/arm64..."
	@GOOS=linux GOARCH=arm64 $(GO) build -o $@ ./example/$(*)

$(OUT_DIR)/%_linux_arm_v6: ./example/%/main.go | $(OUT_DIR)
	@echo "Cross-compiling $(*) for linux/arm (v6)..."
	@GOOS=linux GOARCH=arm GOARM=6 $(GO) build -o $@ ./example/$(*)

# --- Release Build Target (Stripped Binaries) ---
.PHONY: build-release build-release-current build-release-cross
build-release: build-release-current build-release-cross

build-release-current: $(addprefix $(OUT_DIR)/, $(addsuffix _$(CURRENT_OS)_$(CURRENT_ARCH)_release, $(EXAMPLES)))
build-release-cross: $(foreach target, $(TARGETS), \
  $(addprefix $(OUT_DIR)/, $(addsuffix _$(subst /,_,$(target))_release, $(EXAMPLES))))

# Rule to build a specific example for the current system (release)
$(OUT_DIR)/%_$(CURRENT_OS)_$(CURRENT_ARCH)_release: ./example/%/main.go | $(OUT_DIR)
	@echo "Building release $(*) for $(CURRENT_OS)/$(CURRENT_ARCH)..."
	@$(GO) build $(LDFLAGS_RELEASE) -o $@ ./example/$(*)

# Rules to build a specific example for cross-compile targets (release)
$(OUT_DIR)/%_linux_amd64_release: ./example/%/main.go | $(OUT_DIR)
	@echo "Cross-compiling release $(*) for linux/amd64..."
	@GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS_RELEASE) -o $@ ./example/$(*)

$(OUT_DIR)/%_linux_arm64_release: ./example/%/main.go | $(OUT_DIR)
	@echo "Cross-compiling release $(*) for linux/arm64..."
	@GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS_RELEASE) -o $@ ./example/$(*)

$(OUT_DIR)/%_linux_arm_v6_release: ./example/%/main.go | $(OUT_DIR)
	@echo "Cross-compiling release $(*) for linux/arm (v6)..."
	@GOOS=linux GOARCH=arm GOARM=6 $(GO) build $(LDFLAGS_RELEASE) -o $@ ./example/$(*)


# --- Utility Targets ---

# Create the output directory if it doesn't exist
$(OUT_DIR):
	@echo "Creating directory $(OUT_DIR)..."
	@mkdir -p $(OUT_DIR)

# Clean up the output directory
.PHONY: clean
clean:
	@echo "Cleaning $(OUT_DIR)..."
	@rm -rf $(OUT_DIR) 