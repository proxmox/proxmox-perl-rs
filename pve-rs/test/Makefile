.PHONY: test
test: Proxmox/Lib/PVE.pm
	@echo "-- running pve-rs tests --"
	perl -I. -I.. -I../.. ./resource_scheduling.pl

# The test stub, we don't know where to look for the library from in here!
Proxmox/Lib/PVE.pm:
	@echo "run 'make' in the pve-rs/ dir first"
	@exit 1
