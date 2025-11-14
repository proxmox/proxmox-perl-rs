#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use PVE::RS::ResourceScheduling::Static;

my sub score_nodes {
    my ($static, $service) = @_;

    my $score_list = $static->score_nodes_to_start_service($service);

    # imitate HA manager
    my $scores = { map { $_->[0] => -$_->[1] } $score_list->@* };
    my @nodes = sort {
        $scores->{$a} <=> $scores->{$b} || $a cmp $b
    } keys $scores->%*;

    return @nodes;
}

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

	$static->add_service_usage_to_node($nodes[0], "vm:" . (100 + $i), $service);
    }
}

sub test_balance_removal {
    my $static = PVE::RS::ResourceScheduling::Static->new();
    $static->add_node("A", 10, 100_000_000_000);
    $static->add_node("B", 20, 200_000_000_000);
    $static->add_node("C", 30, 300_000_000_000);

    my $service = {
        maxcpu => 4,
        maxmem => 20_000_000_000,
    };

    $static->add_service_usage_to_node("A", "a", $service);
    $static->add_service_usage_to_node("A", "b", $service);
    $static->add_service_usage_to_node("B", "c", $service);
    $static->add_service_usage_to_node("B", "d", $service);
    $static->add_service_usage_to_node("C", "c", $service);

    {
        my @nodes = score_nodes($static, $service);

        is($nodes[0], "C");
        is($nodes[1], "B");
        is($nodes[2], "A");
    }

    $static->remove_service_usage("d");
    $static->remove_service_usage("c");
    $static->add_service_usage_to_node("C", "c", $service);

    {
        my @nodes = score_nodes($static, $service);

        is($nodes[0], "B");
        is($nodes[1], "C");
        is($nodes[2], "A");
    }

    $static->remove_node("B");

    {
        my @nodes = score_nodes($static, $service);

        is($nodes[0], "C");
        is($nodes[1], "A");
    }
}

sub test_overcommitted {
    my $static = PVE::RS::ResourceScheduling::Static->new();
    $static->add_node("A", 4, 4_102_062_080);
    $static->add_node("B", 4, 4_102_062_080);
    $static->add_node("C", 4, 4_102_053_888);
    $static->add_node("D", 4, 4_102_053_888);

    my $service = {
	maxcpu => 1,
	maxmem => 536_870_912,
    };

    $static->add_service_usage_to_node("A", "a", $service);
    $static->add_service_usage_to_node("A", "b", $service);
    $static->add_service_usage_to_node("A", "c", $service);
    $static->add_service_usage_to_node("B", "d", $service);
    $static->add_service_usage_to_node("A", "e", $service);

    my $score_list = $static->score_nodes_to_start_service($service);

    # imitate HA manager
    my $scores = { map { $_->[0] => -$_->[1] } $score_list->@* };
    my @nodes = sort {
	$scores->{$a} <=> $scores->{$b} || $a cmp $b
    } keys $scores->%*;

    is($nodes[0], "C", 'first should be C');
    is($nodes[1], "D", 'second should be D');
    is($nodes[2], "B", 'third should be B');
    is($nodes[3], "A", 'fourth should be A');
}

sub test_balance_small_memory_difference {
    my ($with_start_load) = @_;

    my $static = PVE::RS::ResourceScheduling::Static->new();
    # Memory is different to avoid flaky results with what would otherwise be ties.
    $static->add_node("A", 8, 10_000_000_000);
    $static->add_node("B", 4, 9_000_000_000);
    $static->add_node("C", 4, 8_000_000_000);

    if ($with_start_load) {
	$static->add_service_usage_to_node("A", "vm:100", { maxcpu => 4, maxmem => 1_000_000_000 });
	$static->add_service_usage_to_node("B", "vm:101", { maxcpu => 2, maxmem => 1_000_000_000 });
	$static->add_service_usage_to_node("C", "vm:102", { maxcpu => 2, maxmem => 1_000_000_000 });
    }

    my $service = {
	maxcpu => 3,
	maxmem => 16_000_000,
    };

    for (my $i = 0; $i < 20; $i++) {
	my $score_list = $static->score_nodes_to_start_service($service);

	# imitate HA manager
	my $scores = { map { $_->[0] => -$_->[1] } $score_list->@* };
	my @nodes = sort {
	    $scores->{$a} <=> $scores->{$b} || $a cmp $b
	} keys $scores->%*;

	if ($i % 4 <= 1) {
	    is($nodes[0], "A", 'first should be A');
	    is($nodes[1], "B", 'second should be B');
	    is($nodes[2], "C", 'third should be C');
	} elsif ($i % 4 == 2) {
	    is($nodes[0], "B", 'first should be B');
	    is($nodes[1], "C", 'second should be C');
	    is($nodes[2], "A", 'third should be A');
	} elsif ($i % 4 == 3) {
	    is($nodes[0], "C", 'first should be C');
	    is($nodes[1], "A", 'second should be A');
	    is($nodes[2], "B", 'third should be B');
	} else {
	    die "internal error, got $i % 4 == " . ($i % 4) . "\n";
	}

	$static->add_service_usage_to_node($nodes[0], "vm:" . (103 + $i), $service);
    }
}

test_basic();
test_balance();
test_balance_removal();
test_overcommitted();
test_balance_small_memory_difference(1);
test_balance_small_memory_difference(0);

done_testing();
