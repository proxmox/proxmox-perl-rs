include /usr/share/dpkg/pkg-info.mk

PACKAGE=libpmg-rs-perl

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
export GITVERSION:=$(shell git rev-parse HEAD)

PERL_INSTALLVENDORARCH != perl -MConfig -e 'print $$Config{installvendorarch};'
PERL_INSTALLVENDORLIB != perl -MConfig -e 'print $$Config{installvendorlib};'

MAIN_DEB=$(PACKAGE)_$(DEB_VERSION)_$(ARCH).deb
DBGSYM_DEB=$(PACKAGE)-dbgsym_$(DEB_VERSION)_$(ARCH).deb
DEBS=$(MAIN_DEB) $(DBGSYM_DEB)
DSC=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION).dsc
BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION_UPSTREAM)

DESTDIR=

PM_DIR := PMG

PERLMOD_GENPACKAGE := /usr/lib/perlmod/genpackage.pl \
	--lib=pmg_rs \
	--lib-tag=proxmox \
	--lib-package=Proxmox::Lib::PMG \
	--lib-prefix=PMG

PERLMOD_PACKAGES := \
	  PMG::RS::APT::Repositories \
	  PMG::RS::Acme \
	  PMG::RS::CSR \
	  PMG::RS::OpenId \
	  PMG::RS::TFA

ifeq ($(BUILD_MODE), release)
CARGO_BUILD_ARGS += --release
TARGET_DIR=release
else
TARGET_DIR=debug
endif

all: PMG
	cargo build $(CARGO_BUILD_ARGS)

PMG: Proxmox/Lib/PMG.pm
Proxmox/Lib/PMG.pm:
	$(PERLMOD_GENPACKAGE) $(PERLMOD_PACKAGES)

.PHONY: install
install: target/release/libpmg_rs.so Proxmox/Lib/PMG.pm PMG
	install -d -m755 $(DESTDIR)$(PERL_INSTALLVENDORARCH)/auto
	install -m644 target/release/libpmg_rs.so $(DESTDIR)$(PERL_INSTALLVENDORARCH)/auto/libpmg_rs.so
	install -d -m755 $(DESTDIR)$(PERL_INSTALLVENDORLIB)
	install -d -m755 $(DESTDIR)$(PERL_INSTALLVENDORLIB)/Proxmox/Lib
	install -m644 Proxmox/Lib/PMG.pm $(DESTDIR)$(PERL_INSTALLVENDORLIB)/Proxmox/Lib/PMG.pm
	find $(PM_DIR) \! -type d -print -exec install -Dm644 '{}' $(DESTDIR)$(PERL_INSTALLVENDORLIB)'/{}' ';'

distclean: clean
clean:
	cargo clean
	rm -f *.deb *.dsc *.tar.* *.build *.buildinfo *.changes Cargo.lock
	rm -rf $(PACKAGE)-[0-9]*/

.PHONY: dinstall
dinstall: $(DEBS)
	dpkg -i $(DEBS)

.PHONY: upload
upload: UPLOAD_DIST ?= $(DEB_DISTRIBUTION)
upload: $(DEBS)
	# check if working directory is clean
	git diff --exit-code --stat && git diff --exit-code --stat --staged
	tar cf - $(DEBS) | ssh -X repoman@repo.proxmox.com upload --product pmg --dist $(DEB_DISTRIBUTION)

$(BUILDDIR): src debian common/src Cargo.toml Makefile .cargo/config
	rm -rf $(BUILDDIR) $(BUILDDIR).tmp
	mkdir $(BUILDDIR).tmp
	mkdir $(BUILDDIR).tmp/common
	cp -a -t $(BUILDDIR).tmp src debian Cargo.toml Makefile .cargo
	cp -a -t $(BUILDDIR).tmp/common common/src
	mv $(BUILDDIR).tmp $(BUILDDIR)

.PHONY: deb
deb: $(DEBS)
$(DEBS): $(BUILDDIR)
	cd $(BUILDDIR); PATH="/usr/local/bin:/usr/bin" dpkg-buildpackage -b -us -uc
	lintian $(DEBS)

.PHONY: dsc
dsc: $(DSC)
$(DSC): $(BUILDDIR)
	cd $(BUILDDIR); PATH="/usr/local/bin:/usr/bin" dpkg-buildpackage -S -us -uc -d
	lintian $(DSC)

sbuild: $(DSC)
	sbuild $(DSC)
