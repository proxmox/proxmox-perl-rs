CARGO ?= cargo

ifeq ($(BUILD_MODE), release)
CARGO_BUILD_ARGS += --release
DEBUG_LIBPATH :=
else
DEBUG_LIBPATH := "-L./target/debug", 
endif

define upload_template
	cd build; \
	    dcmd --deb lib$(1)-rs-perl*.changes \
	    | grep -v '.changes$$' \
	    | tar -cf "$@.tar" -T-; \
	    cat "$@.tar" | ssh -X repoman@repo.proxmox.com upload --product $(2) --dist bullseye
endef

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

.PHONY: pve pmg
pve pmg:
	$(CARGO) build $(CARGO_BUILD_ARGS) -p $@-rs

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

pve-deb: build
	cd ./build/pve-rs && dpkg-buildpackage -b -uc -us
	touch $@

pmg-deb: build
	cd ./build/pmg-rs && dpkg-buildpackage -b -uc -us
	touch $@

common-deb: build
	cd ./build/common-pkg && dpkg-buildpackage -b -uc -us
	touch $@

pve-upload: pve-deb
	$(call upload_template,pve,pve)
pmg-upload: pmg-deb
	$(call upload_template,pmg,pmg)

# need to put into variable to ensure comma isn't interpreted as param separator on call
common_target=pve,pmg
common-upload: common-deb
	$(call upload_template,proxmox,$(common_target))

.PHONY: clean
clean:
	cargo clean
	rm -rf ./build ./PVE ./PMG ./pve-deb ./pmg-deb ./common-deb
