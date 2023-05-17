CARGO ?= cargo

ifeq ($(BUILD_MODE), release)
CARGO_BUILD_ARGS += --release
else
endif

.PHONY: all
all:
ifeq ($(BUILD_TARGET), pve)
	$(MAKE) pve
else ifeq ($(BUILD_TARGET), pmg)
	$(MAKE) pmg
else
	@echo "Run one of"
	@echo "  - make pve"
	@echo "  - make pmg"
endif

build:
	rm -rf build
	mkdir build
	echo system >build/rust-toolchain
	cp -a ./Cargo.toml ./build
	cp -a ./common ./build
	cp -a ./pve-rs ./build
	cp -a ./pmg-rs ./build
# Replace the symlinks with copies of the common code in pve/pmg:
	cd build; for i in pve pmg; do \
	  rm ./$$i-rs/common ; \
	  mkdir ./$$i-rs/common ; \
	  cp -R ./common/src ./$$i-rs/common/src ; \
	done
# So the common packages end up in ./build, rather than ./build/common
	mv ./build/common/pkg ./build/common-pkg
# Copy the workspace root into the sources
	mkdir build/pve-rs/.workspace
	cp -t build/pve-rs/.workspace Cargo.toml
	sed -i -e '/\[package\]/a\workspace = ".workspace"' build/pve-rs/Cargo.toml
# Clear the member array and replace it with ".."
	sed -i -e '/^members = \[/,/^]$$/d' build/pve-rs/.workspace/Cargo.toml
	sed -i -e '/^\[workspace\]/a\members = [ ".." ]' build/pve-rs/.workspace/Cargo.toml
# Copy the cargo config
	mkdir build/pve-rs/.cargo
	cp -t build/pve-rs/.cargo .cargo/config
