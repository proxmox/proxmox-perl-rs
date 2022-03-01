include /usr/share/dpkg/default.mk

PACKAGE=libproxmox-rs-perl

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
export GITVERSION:=$(shell git rev-parse HEAD)

PERL_INSTALLVENDORARCH != perl -MConfig -e 'print $$Config{installvendorarch};'
PERL_INSTALLVENDORLIB != perl -MConfig -e 'print $$Config{installvendorlib};'

DEB=${PACKAGE}_${DEB_VERSION}_${ARCH}.deb

DESTDIR=

PM_DIRS := \
	Proxmox/Lib \
	Proxmox/RS

PM_FILES := \
	Proxmox/Lib/Common.pm \
	Proxmox/RS/CalendarEvent.pm

all:
	true

.PHONY: install
install:
	install -d -m755 $(DESTDIR)$(PERL_INSTALLVENDORLIB)
	for i in $(PM_DIRS); do \
	  install -d -m755 $(DESTDIR)$(PERL_INSTALLVENDORLIB)/$$i; \
	done
	for i in $(PM_FILES); do \
	  install -m644 $$i $(DESTDIR)$(PERL_INSTALLVENDORLIB)/$$i; \
	done

.PHONY: deb
deb: $(DEB)
$(DEB): build
	cd build; dpkg-buildpackage -b -us -uc --no-pre-clean
	lintian $(DEBS)
