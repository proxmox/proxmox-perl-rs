package Proxmox::Lib::Common;

=head1 NAME

Proxmox::Lib::Common - base module for rust bindings common between PVE and PMG

=head1 SYNOPSIS

    package Proxmox::RS::CalendarEvent;

    use base 'Proxmox::Lib::Common';

    BEGIN { __PACKAGE__->bootstrap(); }

    1;

=head1 DESCRIPTION

This is the base modules for bindings which are provided by both PVE and PMG. This will ensure that
either Proxmox::Lib::PVE or Proxmox::Lib::PMG have been loaded (in that order) and then use
whichever was loaded.

=cut

use vars qw(@ISA);

sub library {
    return '-current';
}

BEGIN {
    my $data = ($::{'proxmox-rs-library'} //= {});
    my $base = $data->{-package};
    if ($base) {
        push @ISA, $base;
    } else {
        eval { require Proxmox::Lib::PVE and push @ISA, 'Proxmox::Lib::PVE'; };
        eval { require Proxmox::Lib::PMG and push @ISA, 'Proxmox::Lib::PVE'; } if $@;
        die $@ if $@;
    }
}

1;
