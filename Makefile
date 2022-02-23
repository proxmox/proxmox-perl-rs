CARGO ?= cargo

define to_upper
$(shell echo "$(1)" | tr '[:lower:]' '[:upper:]')
endef

ifeq ($(BUILD_MODE), release)
CARGO_BUILD_ARGS += --release
endif

.PHONY: all
all:
ifeq ($(BUILD_TARGET), pve)
	$(MAKE) pve
else ifeq ($(BUILD_TARGET), pmg)
	$(MAKE) pve
else
	@echo "Run 'make pve' or 'make pmg'"
endif

.PHONY: pve pmg
pve pmg:
	@PERLMOD_PRODUCT=$(call to_upper,$@) \
	  $(CARGO) build $(CARGO_BUILD_ARGS) -p $@-rs

build:
	mkdir build
	echo system >build/rust-toolchain
	cp -a ./perl-* ./build/
	cp -a ./pve-rs ./build
	cp -a ./pmg-rs ./build

pve-deb: build
	cd ./build/pve-rs && dpkg-buildpackage -b -uc -us
	touch $@

pmg-deb: build
	cd ./build/pmg-rs && dpkg-buildpackage -b -uc -us
	touch $@

%-upload: %-deb
	cd build; \
	    dcmd --deb lib$*-rs-perl*.changes \
	    | grep -v '.changes$$' \
	    | tar -cf "$@.tar" -T-; \
	    cat "$@.tar" | ssh -X repoman@repo.proxmox.com upload --product $* --dist bullseye

.PHONY: clean
clean:
	cargo clean
	rm -rf ./build ./PVE ./PMG ./pve-deb ./pmg-deb
