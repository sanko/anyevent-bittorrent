#!perl
use strict;
use warnings;
use AnyEvent;
use lib '../../lib', '../../../net-bittorrent-protocol/lib';
use AnyEvent::BitTorrent;
use Test::More;
use File::Temp;
$|++;
my $torrent = q[t/900_data/Sick of Sarah - 2205 BitTorrent Edition.torrent];
chdir '../..' if !-f $torrent;
require t::800_utils::Tracker::HTTP;
my $cv = AE::cv;
my $to = AE::timer(90, 0, sub { diag 'Timeout'; ok 'Timeout'; $cv->send });

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

for my $peer (1..10) {
    $client{$peer} = AnyEvent::BitTorrent->new(
        port    => 0,
        basedir => File::Temp::tempdir('AB_ ' . $peer . '_XXXX', TMPDIR => 1),
        path    => $torrent,
        on_hash_pass => sub {
            pass 'Got piece number ' . pop . ' [' . $client{$peer}->peerid . ']';
            return if $peer <= 3;
            $_->stop for values %client;
            $cv->send;
        },
        on_hash_fail => sub {
            note 'FAIL: ' . pop . ' [' . $client{$peer}->peerid . ']';
        }
    );
    note sprintf 'Opened port %d for %s' , $client{$peer}->port ,$client{$peer}->peerid;
    if ($peer <= 3) {
        $client{$peer}->trackers->[0]->{urls} = [];
    }
    push @{$client{$peer}->trackers}, {
        urls => [
            'http://' . $tracker->host . ':' . $tracker->port . '/announce.pl'
        ],
        complete   => 0,
        incomplete => 0,
        peers      => '',
        ticker     => AE::timer(
            1,
            rand (15),
            sub {
                return if $client{$peer}->state eq 'stopped';
                $client{$peer}->announce();
                note 'Announced from ' . $client{$peer}->peerid
            }
        ),
        failures => 0
    };
}
$cv->recv;
done_testing;
