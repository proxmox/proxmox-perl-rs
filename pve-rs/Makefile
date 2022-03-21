include /usr/share/dpkg/default.mk

PACKAGE=libpve-rs-perl
export PERLMOD_PRODUCT=PVE

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
export GITVERSION:=$(shell git rev-parse HEAD)

PERL_INSTALLVENDORARCH != perl -MConfig -e 'print $$Config{installvendorarch};'
PERL_INSTALLVENDORLIB != perl -MConfig -e 'print $$Config{installvendorlib};'

MAIN_DEB=${PACKAGE}_${DEB_VERSION}_${ARCH}.deb
DBGSYM_DEB=${PACKAGE}-dbgsym_${DEB_VERSION}_${ARCH}.deb
DEBS=$(MAIN_DEB) $(DBGSYM_DEB)

DESTDIR=

PM_DIRS := \
	Proxmox/Lib \
	PVE/RS/APT

PM_FILES := \
	Proxmox/Lib/PVE.pm \
	PVE/RS/APT/Repositories.pm \
	PVE/RS/OpenId.pm \
	PVE/RS/TFA.pm

ifeq ($(BUILD_MODE), release)
CARGO_BUILD_ARGS += --release
endif

all:
ifneq ($(BUILD_MODE), skip)
	cargo build $(CARGO_BUILD_ARGS)
endif

# always re-create this dir
# but also copy the local target/ and PVE/ dirs as a build-cache
.PHONY: build
build:
	rm -rf build
	cargo build --release
	rsync -a debian Makefile Cargo.toml Cargo.lock src target PVE build/

.PHONY: install
install: target/release/libpve_rs.so
	install -d -m755 $(DESTDIR)$(PERL_INSTALLVENDORARCH)/auto
	install -m644 target/release/libpve_rs.so $(DESTDIR)$(PERL_INSTALLVENDORARCH)/auto/libpve_rs.so
	install -d -m755 $(DESTDIR)$(PERL_INSTALLVENDORLIB)/PVE/RS
	set -e && for i in $(PM_DIRS); do \
	  install -d -m755 $(DESTDIR)$(PERL_INSTALLVENDORLIB)/$$i; \
	done
	set -e && for i in $(PM_FILES); do \
	  install -m644 $$i $(DESTDIR)$(PERL_INSTALLVENDORLIB)/$$i; \
	done

.PHONY: deb
deb: $(MAIN_DEB)
$(MAIN_DEB): build
	cd build; dpkg-buildpackage -b -us -uc --no-pre-clean
	lintian $(DEBS)

distclean: clean

clean:
	cargo clean
	rm -rf *.deb *.dsc *.tar.gz *.buildinfo *.changes Cargo.lock build
	find . -name '*~' -exec rm {} ';'

.PHONY: dinstall
dinstall: ${DEBS}
	dpkg -i ${DEBS}

.PHONY: upload
upload: ${DEBS}
	# check if working directory is clean
	git diff --exit-code --stat && git diff --exit-code --stat --staged
	tar cf - ${DEBS} | ssh -X repoman@repo.proxmox.com upload --product pve --dist bullseye
