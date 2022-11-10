#!/usr/bin/perl

use strict;
use warnings;

# FIXME ensure that the just built library is loaded rather than the installed one and add a test
# target to pve-rs/Makefile afterwards. Issue is that the loader looks into an $PATH/auto directory,
# so it's not enough to use lib qw(../target/release)
# Also might be a good idea to test for existence of the files to avoid surprises if the directory
# structure changes in the future.
#use lib qw(..);
#use lib qw(../target/release);
use PVE::RS::ResourceScheduling::Static;

sub assert_num_eq {
    my ($left, $right) = @_;
    my (undef, undef, $line) = caller();
    die "assertion failed: '$left != $right' at line $line\n" if $left != $right;
}

sub assert_str_eq {
    my ($left, $right) = @_;
    my (undef, undef, $line) = caller();
    die "assertion failed: '$left ne $right' at line $line\n" if $left ne $right;
}

sub assert {
    my ($bool) = @_;
    my (undef, undef, $line) = caller();
    die "assertion failed at line $line\n" if !$bool;
}

my $static = PVE::RS::ResourceScheduling::Static->new();
assert_num_eq(scalar($static->list_nodes()->@*), 0);
$static->add_node("A", 10, 100_000_000_000);
assert_num_eq(scalar($static->list_nodes()->@*), 1);
$static->add_node("B", 20, 200_000_000_000);
assert_num_eq(scalar($static->list_nodes()->@*), 2);
$static->add_node("C", 30, 300_000_000_000);
assert_num_eq(scalar($static->list_nodes()->@*), 3);
$static->remove_node("C");
assert_num_eq(scalar($static->list_nodes()->@*), 2);
assert($static->contains_node("A"));
assert($static->contains_node("B"));
assert(!$static->contains_node("C"));

my $service = {
    maxcpu => 4,
    maxmem => 20_000_000_000,
};

for (my $i = 0; $i < 15; $i++) {
    my $score_list = $static->score_nodes_to_start_service($service);

    # imitate HA manager
    my $scores = { map { $_->[0] => -$_->[1] } $score_list->@* };
    my @nodes = sort {
	$scores->{$a} <=> $scores->{$b} || $a cmp $b
    } keys $scores->%*;

    if ($i % 3 == 2) {
	assert_str_eq($nodes[0], "A");
	assert_str_eq($nodes[1], "B");
    } else {
	assert_str_eq($nodes[0], "B");
	assert_str_eq($nodes[1], "A");
    }

    $static->add_service_usage_to_node($nodes[0], $service);
}
