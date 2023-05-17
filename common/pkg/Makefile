include /usr/share/dpkg/pkg-info.mk

PACKAGE=libproxmox-rs-perl

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
export GITVERSION:=$(shell git rev-parse HEAD)

PERL_INSTALLVENDORARCH != perl -MConfig -e 'print $$Config{installvendorarch};'
PERL_INSTALLVENDORLIB != perl -MConfig -e 'print $$Config{installvendorlib};'

DEB=$(PACKAGE)_$(DEB_VERSION)_$(ARCH).deb
DSC=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION).dsc
BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION_UPSTREAM)

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

$(BUILDDIR): debian PVE Proxmox Makefile
	rm -rf $(BUILDDIR) $(BUILDDIR).tmp
	mkdir $(BUILDDIR).tmp
	cp -t $(BUILDDIR).tmp -a debian PVE Proxmox Makefile
	mv $(BUILDDIR).tmp $(BUILDDIR)

.PHONY: deb
deb: $(DEB)
$(DEB): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc --no-pre-clean
	lintian $(DEB)

.PHONY: dsc
dsc: $(DSC)
$(DSC): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -S -us -uc -d
	lintian $(DSC)

sbuild: $(DSC)
	sbuild $(DSC)

.PHONY: upload
upload: UPLOAD_DIST ?= $(DEB_DISTRIBUTION)
upload: $(DEB)
	# check if working directory is clean
	git diff --exit-code --stat && git diff --exit-code --stat --staged
	tar cf - $(DEB) | ssh -X repoman@repo.proxmox.com upload --product pve,pmg --dist $(DEB_DISTRIBUTION)
