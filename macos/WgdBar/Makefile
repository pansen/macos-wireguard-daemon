# Build WgdBar.app: the Rust core, its Swift bindings, the Swift app, and a
# minimal bundle around it. Output: target/WgdBar.app

ROOT := $(abspath ../..)
LIB := $(ROOT)/target/release/libwgd_bar_ffi.a
APP := $(ROOT)/target/WgdBar.app
GEN := .build/bindings
# SwiftPM's own sandbox-exec cannot start inside the nono sandbox.
SWIFT_BUILD := swift build -c release --disable-sandbox

# Release builds pass the tag (without `v`) and the Developer ID identity;
# local builds get a placeholder version and an ad-hoc signature.
VERSION ?= 0.0.0
SIGN_IDENTITY ?= -
ifeq ($(SIGN_IDENTITY),-)
CODESIGN_FLAGS :=
else
# Notarization requires the hardened runtime and a secure timestamp.
CODESIGN_FLAGS := --timestamp --options runtime
endif

# Must match `platforms` in Package.swift and LSMinimumSystemVersion.
export MACOSX_DEPLOYMENT_TARGET := 14.0

.PHONY: app
app: swift
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS
	cp "$$($(SWIFT_BUILD) --show-bin-path)/WgdBar" $(APP)/Contents/MacOS/
	cp Info.plist $(APP)/Contents/
	plutil -replace CFBundleShortVersionString -string "$(VERSION)" $(APP)/Contents/Info.plist
	plutil -replace CFBundleVersion -string "$(VERSION)" $(APP)/Contents/Info.plist
	codesign --force $(CODESIGN_FLAGS) --sign "$(SIGN_IDENTITY)" $(APP)
	codesign --verify --strict --verbose=2 $(APP)
	@echo $(APP)

.PHONY: rust
rust:
	cargo build --manifest-path $(ROOT)/Cargo.toml -p wgd-bar-ffi --release --locked

# Generated files are build output (see .gitignore).
.PHONY: bindings
bindings: rust
	rm -rf $(GEN)
	cargo run -q --manifest-path $(ROOT)/Cargo.toml -p wgd-bar-ffi --release --locked \
		--bin uniffi-bindgen-swift -- \
		--swift-sources --headers --modulemap \
		--module-name wgd_bar_ffiFFI --modulemap-filename module.modulemap \
		$(LIB) $(GEN)
	cp $(GEN)/wgd_bar_ffi.swift Sources/WgdBar/Generated.swift
	mkdir -p Sources/wgd_bar_ffiFFI
	cp $(GEN)/wgd_bar_ffiFFI.h $(GEN)/module.modulemap Sources/wgd_bar_ffiFFI/

.PHONY: swift
swift: bindings
	$(SWIFT_BUILD)

.PHONY: run
run: app stop
	open $(APP)

# Quit a running instance, so `run` starts the fresh build instead of
# `open` bringing the old process forward.
.PHONY: stop
stop:
	@pkill -x WgdBar && echo "stopped running WgdBar" || true
	@while pgrep -x WgdBar >/dev/null; do sleep 0.1; done

.PHONY: clean
clean:
	rm -rf .build $(APP) Sources/WgdBar/Generated.swift \
		Sources/wgd_bar_ffiFFI/wgd_bar_ffiFFI.h Sources/wgd_bar_ffiFFI/module.modulemap
