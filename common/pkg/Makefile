include /usr/share/dpkg/default.mk

PACKAGE=libproxmox-rs-perl

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
export GITVERSION:=$(shell git rev-parse HEAD)

PERL_INSTALLVENDORARCH != perl -MConfig -e 'print $$Config{installvendorarch};'
PERL_INSTALLVENDORLIB != perl -MConfig -e 'print $$Config{installvendorlib};'

DEB=${PACKAGE}_${DEB_VERSION}_${ARCH}.deb

DESTDIR=

all:
	true

.PHONY: install
install:
	install -d -m755 $(DESTDIR)$(PERL_INSTALLVENDORLIB)
	find PVE \! -type d -print -exec install -Dm644 '{}' $(DESTDIR)$(PERL_INSTALLVENDORLIB)'/{}' ';'
	find Proxmox \! -type d -print -exec install -Dm644 '{}' $(DESTDIR)$(PERL_INSTALLVENDORLIB)'/{}' ';'
	rm $(DESTDIR)$(PERL_INSTALLVENDORLIB)'/Proxmox/Lib/template.pm'

.PHONY: deb
deb: $(DEB)
$(DEB): build
	cd build; dpkg-buildpackage -b -us -uc --no-pre-clean
	lintian $(DEBS)
