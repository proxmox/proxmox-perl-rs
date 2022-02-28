#!/usr/bin/env perl

# Create a perl package given a product and package name.

use strict;
use warnings;

use File::Path qw(make_path);

my $product = shift @ARGV or die "missing product name (PVE, PMG or Common)\n";

die "missing package name\n" if !@ARGV;

for my $package (@ARGV) {
    my $path = ($package =~ s@::@/@gr) . ".pm";

    print "Generating $path\n";

    $path =~ m@^(.*)/[^/]+@;
    make_path($1, { mode => 0755 });

    open(my $fh, '>', $path) or die "failed to open '$path' for writing: $!\n";

    print {$fh} <<"EOF";
package $package;
use base 'Proxmox::Lib::$product';
BEGIN { __PACKAGE__->bootstrap(); }
1;
EOF

    close($fh);
}
