package Proxmox::APT::HistoryAPI;

# The methods of the APT history API, shared by the products, which register them with their own
# permissions.

use strict;
use warnings;

use HTTP::Status qw(:constants);

use PVE::Exception qw(raise);
use PVE::JSONSchema qw(get_standard_option);

use Proxmox::RS::APT::History;

my $package_name_pattern = qr/[a-z0-9][-+.a-z0-9]+/;

my sub package_change {
    return {
        type => 'object',
        properties => {
            action => {
                description => "What the transaction did to the package.",
                type => 'string',
                enum => [
                    'install',
                    'reinstall',
                    'upgrade',
                    'downgrade',
                    'remove',
                    'purge',
                    'disappear',
                ],
            },
            package => {
                description => "Package name.",
                type => 'string',
            },
            arch => {
                description => "Package architecture.",
                type => 'string',
                optional => 1,
            },
            'old-version' => {
                description => "Version installed before the transaction.",
                type => 'string',
                optional => 1,
            },
            'new-version' => {
                description => "Version installed by the transaction.",
                type => 'string',
                optional => 1,
            },
            automatic => {
                description =>
                    "Whether APT marked the newly installed package as installed automatically.",
                type => 'boolean',
                optional => 1,
                default => 0,
            },
        },
    };
}

my sub transaction_parameters {
    return (
        node => get_standard_option('pve-node'),
        'start-time' => {
            description => "Start time of the transaction, as listed in the APT history.",
            type => 'integer',
        },
        'start-index' => {
            description => "Start index of the transaction, as listed in the APT history.",
            type => 'integer',
            minimum => 0,
            maximum => 4294967295,
            optional => 1,
            default => 0,
        },
    );
}

sub history_method {
    my ($permissions) = @_;

    return {
        name => 'history',
        path => 'history',
        method => 'GET',
        description => "List past APT transactions and their package changes, newest first.",
        permissions => $permissions,
        # hardened systems can restrict access to the rotated APT logs or their directory
        protected => 1,
        proxyto => 'node',
        parameters => {
            additionalProperties => 0,
            properties => {
                node => get_standard_option('pve-node'),
                since => {
                    description =>
                        "Only list transactions that started at or after this Unix epoch.",
                    type => 'integer',
                    optional => 1,
                },
                until => {
                    description =>
                        "Only list transactions that started at or before this Unix epoch.",
                    type => 'integer',
                    optional => 1,
                },
                package => {
                    description => "Only list transactions that changed this package.",
                    pattern => $package_name_pattern,
                    typetext => '<package>',
                    type => 'string',
                    optional => 1,
                },
                limit => {
                    description => "List at most this many transactions.",
                    type => 'integer',
                    minimum => 1,
                    optional => 1,
                },
            },
        },
        returns => {
            type => 'array',
            items => {
                type => 'object',
                properties => {
                    'start-time' => {
                        description => "Start time as Unix epoch.",
                        type => 'integer',
                        renderer => 'timestamp',
                    },
                    'start-index' => {
                        description => "Number of earlier transactions with the same start time"
                            . " in the same log file. Together with the start time, this"
                            . " identifies the transaction.",
                        type => 'integer',
                        minimum => 0,
                        optional => 1,
                        default => 0,
                    },
                    'end-time' => {
                        description => "End time as Unix epoch, missing if the transaction is"
                            . " still running or got interrupted.",
                        type => 'integer',
                        optional => 1,
                        renderer => 'timestamp',
                    },
                    'command-line' => {
                        description => "Command line of the APT invocation.",
                        type => 'string',
                        optional => 1,
                    },
                    'requested-by' => {
                        description => "User who requested the transaction through sudo, pkexec"
                            . " or PackageKit.",
                        type => 'string',
                        optional => 1,
                    },
                    'requested-by-uid' => {
                        description => "UID of the user who requested the transaction.",
                        type => 'integer',
                        optional => 1,
                    },
                    comment => {
                        description =>
                            "Comment set through the 'APT::History::Comment' option.",
                        type => 'string',
                        optional => 1,
                    },
                    error => {
                        description => "Error reported for the transaction, usually by dpkg.",
                        type => 'string',
                        optional => 1,
                    },
                    packages => {
                        description => "Changed packages, in the order APT logged them.",
                        type => 'array',
                        items => package_change(),
                    },
                },
            },
        },
        code => sub {
            my ($param) = @_;

            return Proxmox::RS::APT::History::list_history($param);
        },
    };
}

sub term_log_method {
    my ($permissions) = @_;

    return {
        name => 'termlog',
        path => 'termlog',
        method => 'GET',
        description => "Get the terminal output of a past APT transaction.",
        permissions => $permissions,
        # the APT terminal log is only readable for root and the adm group
        protected => 1,
        proxyto => 'node',
        parameters => {
            additionalProperties => 0,
            properties => {
                transaction_parameters(),
                format => {
                    description =>
                        "Format of the output, 'styled' keeps bold, dim and the basic"
                        . " foreground colors as SGR escape sequences, each setting the complete"
                        . " style and none spanning a line break.",
                    type => 'string',
                    enum => ['plain', 'styled'],
                    optional => 1,
                    default => 'plain',
                },
            },
        },
        returns => {
            description => "The terminal output.",
            type => 'string',
        },
        code => sub {
            my ($param) = @_;

            my $start_time = int($param->{'start-time'});
            my $start_index = int($param->{'start-index'} // 0);
            my $log = Proxmox::RS::APT::History::get_term_log(
                $start_time, $start_index, $param->{format},
            );
            raise(
                "no terminal output found for the APT transaction started at $start_time"
                    . " with index $start_index\n",
                code => HTTP_NOT_FOUND,
            ) if !defined($log);

            return $log;
        },
    };
}

1;
