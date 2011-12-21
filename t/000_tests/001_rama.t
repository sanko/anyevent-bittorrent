#!perl
use AnyEvent;
use lib '../../lib', '../../../net-bittorrent-protocol/lib';
use AnyEvent::BitTorrent;
use Net::BitTorrent::Protocol qw[:all];
use Test::More;
use File::Temp;
$|++;
my $torrent = q[t/900_data/rama's test creator - ia test.torrent];
my $basedir = File::Temp::tempdir('AB_XXXX', TMPDIR => 1);
chdir '../..' if !-f $torrent;
my $cv = AE::cv;
my $to = AE::timer(60, 0, sub { diag 'Timeout'; $cv->send });

#
my $client;
$client = AnyEvent::BitTorrent->new(
    basedir      => $basedir,
    path         => $torrent,
    on_hash_pass => sub {
        pass 'Got piece number ' . pop;
        return
            if scalar grep {$_} split '',
            substr unpack('b*', $client->wanted), 0, $client->piece_count + 1;
        $client->stop;
        $cv->send;
    },
    on_hash_fail => sub { note 'FAIL: ' . pop }
);

#
like $client->peerid, qr[^-AB\d{4}-.{12}$], 'peerid( )';
is $client->infohash, pack('H*', '4005ae91492980463df37ada424966b04ec30c53'),
    'infohash( )';
is $client->size, 462163, 'size( )';
is $client->name, "Rama's test creator - IA Test", 'name( )';
$client->hashcheck();
note 'Now, we get to work';
$cv->recv;
done_testing;
