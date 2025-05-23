include /usr/share/dpkg/pkg-info.mk

PACKAGE=libproxmox-rs-perl

ARCH:=all
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

PERLMOD_PACKAGES := \
	  Proxmox::RS::APT::Repositories \
	  Proxmox::RS::CalendarEvent \
	  Proxmox::RS::Notify \
	  Proxmox::RS::OIDC \
	  Proxmox::RS::SharedCache \
	  Proxmox::RS::Subscription

PERLMOD_PACKAGE_FILES := $(addsuffix .pm,$(subst ::,/,$(PERLMOD_PACKAGES)))

Proxmox/RS: $(PERLMOD_PACKAGE_FILES)
$(PERLMOD_PACKAGE_FILES) &:
	$(PERLMOD_GENPACKAGE) $(PERLMOD_PACKAGES)

all: Proxmox/RS
	true

.PHONY: install
install: Proxmox/RS
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
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
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

clean:
	rm -f *.deb *.dsc *.tar.* *.build *.buildinfo *.changes
	rm -rf $(PACKAGE)-[0-9]*/
	rm -rf Proxmox/RS
