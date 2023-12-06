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
        eval { require Proxmox::Lib::PMG and push @ISA, 'Proxmox::Lib::PMG'; } if $@;
        die $@ if $@;
    }
}

=head1 Environment Variable Safety

Perl's handling of environment variables was completely messed up until v5.38.
Using `setenv` such as use din the `openssl-probe` crate would cause it to
crash later on, therefore we provide a perl-version of env var probing instead,
and override the crate with one that doesn't replace the variables if they are
already set correctly.

=cut

# Copied from openssl-probe
my @cert_dirs = (
    "/var/ssl",
    "/usr/share/ssl",
    "/usr/local/ssl",
    "/usr/local/openssl",
    "/usr/local/etc/openssl",
    "/usr/local/share",
    "/usr/lib/ssl",
    "/usr/ssl",
    "/etc/openssl",
    "/etc/pki/ca-trust/extracted/pem",
    "/etc/pki/tls",
    "/etc/ssl",
    "/etc/certs",
    "/opt/etc/ssl",
    "/data/data/com.termux/files/usr/etc/tls",
    "/boot/system/data/ssl",
);

# Copied from openssl-probe
my @cert_file_names = (
    "cert.pem",
    "certs.pem",
    "ca-bundle.pem",
    "cacert.pem",
    "ca-certificates.crt",
    "certs/ca-certificates.crt",
    "certs/ca-root-nss.crt",
    "certs/ca-bundle.crt",
    "CARootCertificates.pem",
    "tls-ca-bundle.pem",
);

my sub probe_ssl_vars : prototype() {
    my $result_file = $ENV{SSL_CERT_FILE};
    my $result_file_changed = 0;
    my $result_dir = $ENV{SSL_CERT_DIR};
    my $result_dir_changed = 0;

    for my $certs_dir (@cert_dirs) {
	if (!defined($result_file)) {
	    for my $file (@cert_file_names) {
		my $path = "$certs_dir/$file";
		if (-e $path) {
		    $result_file = $path;
		    $result_file_changed = 1;
		    last;
		}
	    }
	}
	if (!defined($result_dir)) {
	    for my $file (@cert_file_names) {
		my $path = "$certs_dir/certs";
		if (-d $path) {
		    $result_dir = $path;
		    $result_dir_changed = 1;
		    last;
		}
	    }
	}
	last if defined($result_file) && defined($result_dir);
    }

    if ($result_file_changed && defined($result_file)) {
	$ENV{SSL_CERT_FILE} = $result_file;
    }
    if ($result_dir_changed && defined($result_dir)) {
	$ENV{SSL_CERT_DIR} = $result_dir;
    }
}

probe_ssl_vars();

1;
