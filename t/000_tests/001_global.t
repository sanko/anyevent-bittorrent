#!perl
use AnyEvent;
use lib '../../lib', '../../../net-bittorrent-protocol/lib';
use AnyEvent::BitTorrent;
use Net::BitTorrent::Protocol qw[:all];
use Test::More;
use File::Temp;
$|++;
my $torrent = q[t/900_data/Sick of Sarah - 2205 BitTorrent Edition.torrent];
my $basedir = File::Temp::tempdir('AB_XXXX', TMPDIR => 1);
chdir '../..' if !-f $torrent;
my $cv = AE::cv;
my $client;
my $to = AE::timer(60, 0, sub { diag sprintf 'Timeout!'; $cv->send });

#
$client = AnyEvent::BitTorrent->new(
    basedir      => $basedir,
    path         => $torrent,
    on_hash_pass => sub {
        pass 'Got piece number ' . pop;
        return if !$client->complete;
        $client->stop;
        $cv->send;
    },
    on_hash_fail => sub { note 'FAIL: ' . pop }
);

#
like $client->peerid, qr[^-AB\d{3}[SU]-.{12}$], 'peerid( )';
is $client->infohash, pack('H*', 'ecd2f1ffad3c0cc8b20615b137705af655dbb6a9'),
    'infohash( )';
is $client->size, 51599856, 'size( )';
is $client->name, 'Sick of Sarah - 2205 BitTorrent Edition', 'name( )';
like $client->reserved, qr[^.{8}$], 'reserved( )';    # Weak test
$client->hashcheck();
note 'Now, we get to work';
$cv->recv;    # Pulls one full piece and quits
done_testing;
