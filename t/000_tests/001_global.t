#!perl
use AnyEvent;
use lib '../../lib', '../../../net-bittorrent-protocol/lib';
use AnyEvent::BitTorrent;
use Net::BitTorrent::Protocol qw[:all];
use Test::More;
use File::Temp;
$|++;
my $torrent = q[t/900_data/kubuntu-active-13.04-desktop-i386.iso.torrent];
my $basedir = File::Temp::tempdir('AB_XXXX', TMPDIR => 1);
chdir '../..' if !-f $torrent;
my $cv = AE::cv;
my $client;
my $to = AE::timer(90, 0, sub { diag 'Timeout'; ok 'Timeout'; $cv->send });
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
is $client->infohash, pack('H*', 'c5588b4606dd1d58e7fb93d8c067e9bf2b50a864'),
    'infohash( )';
is $client->size, 1102970880, 'size( )';
is $client->name, 'kubuntu-active-13.04-desktop-i386.iso', 'name( )';
like $client->reserved, qr[^.{8}$], 'reserved( )';    # Weak test
$client->hashcheck();
note 'Now, we get to work';
$cv->recv;    # Pulls one full piece and quits
done_testing;
