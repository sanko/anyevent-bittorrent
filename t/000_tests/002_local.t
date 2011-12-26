#!perl
use strict;
use warnings;
use AnyEvent;
use lib '../../lib', '../../../net-bittorrent-protocol/lib';
use AnyEvent::BitTorrent;
use Test::More;
use File::Temp;
$|++;
my $torrent = q[t/900_data/rama's test creator - ia test.torrent];
chdir '../..' if !-f $torrent;
require t::800_utils::Tracker::HTTP;
my $cv = AE::cv;
my $to = AE::timer(90, 0, sub { diag 'Timeout'; $cv->send });

#
my $tracker =
    t::800_utils::Tracker::HTTP->new(host     => '127.0.0.1',
                                     interval => 15,
                                     port     => 0
    );
note 'HTTP tracker @ http://'
    . $tracker->host . ':'
    . $tracker->port
    . '/announce.pl';
my %client;
my @ports = 1338 .. 1339;
for my $port (@ports) {
    $client{$port} = AnyEvent::BitTorrent->new(
        port    => $port,
        basedir => File::Temp::tempdir('AB_ ' . $port . '_XXXX', TMPDIR => 1),
        path    => $torrent,
        on_hash_pass => sub {
            pass 'Got piece number ' . pop . ' [' . $port . ']';
            return if $port == $ports[0];
            $client{$_}->stop for @ports;
            $cv->send;
        },
        on_hash_fail => sub {
            note 'FAIL: ' . pop . ' [' . $port . ']';
        }
    );
    if ($port != $ports[0]) {
        $client{$port}->trackers->[0]->{urls} = [];
    }
    push @{$client{$port}->trackers}, {
        urls => [
            'http://' . $tracker->host . ':' . $tracker->port . '/announce.pl'
        ],
        complete   => 0,
        incomplete => 0,
        peers      => '',
        ticker     => AE::timer(
            1,
            15 * 60,
            sub {
                return if $client{$port}->state eq 'stopped';
                $client{$port}->announce();
            }
        ),
        failures => 0
    };
}
$cv->recv;
done_testing;
