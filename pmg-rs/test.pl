#!/usr/bin/env perl

use v5.28.0;
use Data::Dumper;

use lib '.';
use PMG::RS::Acme;
use PMG::RS::CSR;

# "Config:" The Acme server URL:
my $DIR = 'https://acme-staging-v02.api.letsencrypt.org/directory';

# Useage:
#
# * Create a new account:
#     | ~/ $ ./test.pl ./account.json new 'somebody@example.invalid"
#
#   The `./account.json` will be created using an EC P-256 key.
#   Optionally an RSA key size can be passed as additional parameter to generate
#   an account with an RSA key instead.
#
# From here on out the `./account.json` file must already exist:
#
# * Place a new order:
#     | ~/ $ ./test.pl ./account.json new-order my.domain.com
#     | $VAR1 = {
#     |     ... order data ...
#     |     'authorizations' => [
#     |         'https://acme.example/auths/1244',
#     |         ... possibly more ...
#     |     ]
#     | }
#     | Order URL: https://acme.example/order/1793
#
#   Note: This   ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^
#     URL will be used later for finalization and certifiate download.
#   The `$VAR1` dump contains the order JSON data.
#   The 'authorizations' URLs are going to be used next.
#
# * Get authorization info
#     | ~/ $ ./test.pl ./account.json get-auth 'https://acme.example/auths/1244'
#     | $VAR1 = {
#     |     ... auth data ...
#     |     'challenges' => [
#     |         {
#     |             'type' => 'dns-01',
#     |             'url' => 'https://acme.example/challenge/8188/dns1'
#     |         }
#     |         ... likely more ...
#     |     ]
#     | }
#     | Key Authorization = SuperVeryMegaLongValue
#     | dns-01 TXT value = ShorterValue
#
#   Now perform the things you need to for the challenge, eg. setup the DNS
#   entry using the provided TXT value.
#   Then use the correct challenge's URL with req-auth
#
# * Request challenge validation
#     | ~/ $ ./test.pl ./account.json \
#     |      req-challenge 'https://acme.example/challenge/8188/dns1
#
# * Repeat the above 2 steps for all authorizations.
# * Wait for the order to be valid via `get-order`
#     | ~/ $ ./test.pl ./account.json get-order 'https://acme.example/order/1793'
#     | $VAR1 = {
#     |     'status' => 'valid',
#     |     'finalize' => 'some URL',
#     |     ... order data ...
#     | }
#     | Order URL: https://acme.example/order/1793
#
# * Finalize the order via the *Order URL* and a private key to sign the
#   request with (eg. generated via `openssl genrsa` or `openssl ecparam`).
#     | ~/ $ ./test.pl ./account.json \
#     |      finalize my.domain.com ./my-private-key.pem \
#     |      'https://acme.example/order/1793'
#
# * Wait for a 'certificate' property to pop up in the order
#   (check via 'get-order')
#
# * Grab the certificate with the Order URL and a destination file name:
#     | ~/ $ ./test.pl ./account.json get-cert \
#     |      'https://acme.example/order/1793' \
#     |      ./my-cert.pem


my $account = shift // die "missing account file\n";
my $cmd = shift // die "missing account file\n";

sub load : prototype($) {
    my ($file) = @_;
    open(my $fh, '<', $file) or die "open($file): $!\n";
    my $data = do {
        local $/ = undef;
        <$fh>
    };
    close($fh);
    return $data;
}

sub store : prototype($$) {
    my ($file, $data) = @_;
    open(my $fh, '>', $file) or die "open($file): $!\n";
    syswrite($fh, $data) == length($data)
        or die "failed to write data to $file: $!\n";
    close($fh);
}

if ($cmd eq 'new') {
    my $mail = shift // die "missing mail address\n";
    my $rsa_bits = shift;
    if (defined($rsa_bits)) {
        $rsa_bits = int($rsa_bits);
    }
    my $acme = PMG::RS::Acme->new($DIR);
    $acme->new_account($account, 1, ["mailto:$mail"], undef);
} elsif ($cmd eq 'get-meta') {
    #my $acme = PMG::RS::Acme->new($DIR);
    my $acme = PMG::RS::Acme->new('https%3A%2F%2Facme-v02.api.letsencrypt.org%2Fdirectory');
    my $data = $acme->get_meta();
    say Dumper($data);
} elsif ($cmd eq 'new-order') {
    my $domain = shift // die "missing domain\n";
    my $acme = PMG::RS::Acme->load($account);
    my ($url, $order) = $acme->new_order([$domain]);
    say Dumper($order);
    say "Order URL: $url\n";
} elsif ($cmd eq 'get-auth') {
    my $url = shift // die "missing url\n";
    my $acme = PMG::RS::Acme->load($account);
    my $auth = $acme->get_authorization($url);
    say Dumper($auth);
    for my $challenge ($auth->{challenges}->@*) {
        next if $challenge->{type} ne 'dns-01';
        say "Key Authorization = ".$acme->key_authorization($challenge->{token});
        say "dns-01 TXT value = ".$acme->dns_01_txt_value($challenge->{token});
    }
} elsif ($cmd eq 'req-challenge') {
    my $url = shift // die "missing url\n";
    my $acme = PMG::RS::Acme->load($account);
    my $challenge = $acme->request_challenge_validation($url);
    say Dumper($challenge);
} elsif ($cmd eq 'finalize') {
    my $domain = shift // die 'missing domain\n';
    my $pkfile = shift // die "missing private key file\n";
    my $order_url = shift // die "missing order URL\n";
    my ($csr_der, $pkey_pem) = PMG::RS::CSR::generate_csr([$domain], {});
    store($pkfile, $pkey_pem);
    my $acme = PMG::RS::Acme->load($account);
    my $order = $acme->get_order($order_url);
    say Dumper($order);
    die "order not ready\n" if $order->{status} ne 'ready';
    $acme->finalize_order($order->{finalize}, $csr_der);
} elsif ($cmd eq 'get-order') {
    my $order_url = shift // die "missing order URL\n";
    my $acme = PMG::RS::Acme->load($account);
    my $order = $acme->get_order($order_url);
    say Dumper($order);
} elsif ($cmd eq 'get-cert') {
    my $order_url = shift // die "missing order URL\n";
    my $file_name = shift // die "missing destination file name\n";
    my $acme = PMG::RS::Acme->load($account);
    my $order = $acme->get_order($order_url);
    my $cert_url = $order->{certificate};
    die "certificate not ready\n" if !$cert_url;
    say Dumper($order);
    my $cert = $acme->get_certificate($cert_url);
    store($file_name, $cert);
} else {
    die "unknown command '$cmd'\n";
}
