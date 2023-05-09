include /usr/share/dpkg/default.mk

PACKAGE=libproxmox-rs-perl

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
export GITVERSION:=$(shell git rev-parse HEAD)

PERL_INSTALLVENDORARCH != perl -MConfig -e 'print $$Config{installvendorarch};'
PERL_INSTALLVENDORLIB != perl -MConfig -e 'print $$Config{installvendorlib};'

DEB=${PACKAGE}_${DEB_VERSION}_${ARCH}.deb

DESTDIR=

PERLMOD_GENPACKAGE := /usr/lib/perlmod/genpackage.pl \
	--lib=- \
	--lib-tag=proxmox \
	--lib-package=Proxmox::Lib::Common \
	--lib-prefix=Proxmox

# Point to any generated pm file (Proxmox/ dir is already present in this package)
Proxmox/RS/CalendarEvent.pm:
	$(PERLMOD_GENPACKAGE) \
	  Proxmox::RS::APT::Repositories \
	  Proxmox::RS::CalendarEvent \
	  Proxmox::RS::Subscription

all: Proxmox/RS/CalendarEvent.pm
	true

.PHONY: install
install: Proxmox/RS/CalendarEvent.pm
	install -d -m755 $(DESTDIR)$(PERL_INSTALLVENDORLIB)
	find PVE \! -type d -print -exec install -Dm644 '{}' $(DESTDIR)$(PERL_INSTALLVENDORLIB)'/{}' ';'
	find Proxmox \! -type d -print -exec install -Dm644 '{}' $(DESTDIR)$(PERL_INSTALLVENDORLIB)'/{}' ';'

.PHONY: deb
deb: $(DEB)
$(DEB): build
	cd build; dpkg-buildpackage -b -us -uc --no-pre-clean
	lintian $(DEBS)
