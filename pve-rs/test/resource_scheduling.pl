#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use PVE::RS::ResourceScheduling::Static;

sub test_basic {
    my $static = PVE::RS::ResourceScheduling::Static->new();
    is(scalar($static->list_nodes()->@*), 0, 'node list empty');
    $static->add_node("A", 10, 100_000_000_000);
    is(scalar($static->list_nodes()->@*), 1, '1 node added');
    $static->add_node("B", 20, 200_000_000_000);
    is(scalar($static->list_nodes()->@*), 2, '2nd node');
    $static->add_node("C", 30, 300_000_000_000);
    is(scalar($static->list_nodes()->@*), 3, '3rd node');
    $static->remove_node("C");
    is(scalar($static->list_nodes()->@*), 2, '3rd removed should be 2');
    ok($static->contains_node("A"), 'should contain a node A');
    ok($static->contains_node("B"), 'should contain a node B');
    ok(!$static->contains_node("C"), 'should not contain a node C');
}

sub test_balance {
    my $static = PVE::RS::ResourceScheduling::Static->new();
    $static->add_node("A", 10, 100_000_000_000);
    $static->add_node("B", 20, 200_000_000_000);

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
	    is($nodes[0], "A", 'first should be A');
	    is($nodes[1], "B", 'second should be A');
	} else {
	    is($nodes[0], "B", 'first should be B');
	    is($nodes[1], "A", 'second should be A');
	}

	$static->add_service_usage_to_node($nodes[0], $service);
    }
}

test_basic();
test_balance();

done_testing();
