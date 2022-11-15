CARGO ?= cargo

ifeq ($(BUILD_MODE), release)
CARGO_BUILD_ARGS += --release
DEBUG_LIBPATH :=
else
DEBUG_LIBPATH := "-L./target/debug", 
endif

define package_template
	sed -r \
	  -e 's/\{\{PRODUCT\}\}/$(1)/g;' \
	  -e 's/\{\{LIBRARY\}\}/$(2)/g;' \
	  -e 's|\{\{DEBUG_LIBPATH\}\}|$(DEBUG_LIBPATH)|g;' \
	  Proxmox/Lib/template.pm \
	  >Proxmox/Lib/$(1).pm
endef

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

.PHONY: gen
gen:
	$(call package_template,PMG,pmg_rs)
	$(call package_template,PVE,pve_rs)
	perl ./scripts/genpackage.pl Common \
	  Proxmox::RS::APT::Repositories \
	  Proxmox::RS::CalendarEvent \
	  Proxmox::RS::Subscription
	perl ./scripts/genpackage.pl PVE \
	  PVE::RS::APT::Repositories \
	  PVE::RS::OpenId \
	  PVE::RS::ResourceScheduling::Static \
	  PVE::RS::TFA
	perl ./scripts/genpackage.pl PMG \
	  PMG::RS::APT::Repositories \
	  PMG::RS::Acme \
	  PMG::RS::CSR \
	  PMG::RS::OpenId \
	  PMG::RS::TFA

build:
	rm -rf build
	mkdir build
	echo system >build/rust-toolchain
	cp -a ./scripts ./build
	cp -a ./common ./build
	cp -a ./pve-rs ./build
	cp -a ./pmg-rs ./build
	cp -a ./Proxmox ./build
	$(MAKE) BUILD_MODE=release -C build -f ../Makefile gen
	mkdir -p ./build/pve-rs/Proxmox/Lib
	mv ./build/Proxmox/Lib/PVE.pm ./build/pve-rs/Proxmox/Lib/PVE.pm
	mkdir -p ./build/pmg-rs/Proxmox/Lib
	mv ./build/Proxmox/Lib/PMG.pm ./build/pmg-rs/Proxmox/Lib/PMG.pm
	mv ./build/PVE ./build/pve-rs
	mv ./build/PMG ./build/pmg-rs
	mv ./build/Proxmox ./build/common/pkg
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
