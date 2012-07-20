package AnyEvent::BitTorrent;
{ $AnyEvent::BitTorrent::VERSION = 'v0.1.8' }
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use AnyEvent::HTTP;
use Any::Moose;
use Any::Moose '::Util::TypeConstraints';
use Fcntl qw[/SEEK_/ /O_/ :flock];
use Digest::SHA qw[sha1];
use File::Spec;
use File::Path;
use Net::BitTorrent::Protocol qw[:all];

#
# XXX - These should be ro attributes w/o init args:
my $block_size = 2**14;

#
has port => (is      => 'ro',
             isa     => 'Int',
             default => 0,
             writer  => '_set_port'
);
has socket => (is        => 'ro',
               isa       => 'Ref',
               init_arg  => undef,
               required  => 1,
               predicate => '_has_socket',
               builder   => '_build_socket'
);

sub _build_socket {
    my $s = shift;
    tcp_server undef, $s->port, sub {
        my ($fh, $host, $port) = @_;
        return $fh->destroy if $s->state eq 'stopped';
        my $handle = AnyEvent::Handle->new(
            fh       => $fh,
            on_error => sub {
                my ($hdl, $fatal, $msg) = @_;

                # XXX - callback
                #AE::log error => "got error $msg\n";
                $s->_del_peer($hdl);
            },
            on_eof => sub {
                my $h = shift;
                $s->_del_peer($h);
            },
            on_read => sub { $s->_on_read_incoming(@_) }
        );
        $s->_add_peer($handle);
        }, sub {
        my ($fh, $thishost, $thisport) = @_;
        $s->_set_port($thisport);

        #AE::log info => "bound to $thishost, port $thisport";
        };
}
has path => (
            is  => 'ro',
            isa => subtype(
                as 'Str' => where { -f $_ } => message { 'Cannot find ' . $_ }
            ),
            required => 1
);
has reserved => (is         => 'ro',
                 isa        => subtype(as 'Str' => where { length $_ == 8 }),
                 lazy_build => 1
);

sub _build_reserved {
    my $reserved = "\0" x 8;

    #vec($reserved, 5, 8)  = 0x10;    # Ext Protocol
    vec($reserved, 7, 8) = 0x04;    # Fast Ext
    $reserved;
}
has peerid => (
    is  => 'ro',
    isa => subtype(
        as 'Str' => where { length $_ == 20 } => message {
            'Peer ID must be 20 chars in length';
        }
    ),
    init_arg => undef,
    required => 1,
    default  => sub {
        pack(
            'a20',
            (sprintf(
                 '-AB%01d%01d%01d%1s-%7s%-5s',
                 ($AnyEvent::BitTorrent::VERSION =~ m[^v(\d+)\.(\d+)\.(\d+)]),
                 ($AnyEvent::BitTorrent::VERSION =~ m[[^\d\.^v]] ? 'U' : 'S'),
                 (join '',
                  map {
                      ['A' .. 'Z', 'a' .. 'z', 0 .. 9, qw[- . _ ~]]
                      ->[rand(66)]
                      } 1 .. 7
                 ),
                 [qw[KaiLi April Aaron]]->[rand 3]
             )
            )
        );
    }
);
has bitfield => (is         => 'ro',
                 isa        => 'Str',
                 init_arg   => undef,
                 lazy_build => 1
);
sub _build_bitfield { pack 'b*', "\0" x shift->piece_count }

sub wanted {
    my $s      = shift;
    my $wanted = '';
    for my $findex (0 .. $#{$s->files}) {
        my $prio = !!$s->files->[$findex]{priority};
        for my $index ($s->_file_to_range($findex)) {
            vec($wanted, $index, 1) = $prio && !vec($s->bitfield, $index, 1);
        }
    }
    $wanted;
}

sub complete {
    my $s = shift;
    -1 == index substr(unpack('b*', $s->wanted), 0, $s->piece_count + 1), 1;
}

sub seed {
    my $s = shift;
    -1 == index substr(unpack('b*', $s->bitfield), 0, $s->piece_count + 1), 0;
}

sub _left {
    my $s = shift;
    $s->piece_length * scalar grep {$_} split '',
        substr unpack('b*', $s->wanted), 0, $s->piece_count + 1;
}
has $_ => (is      => 'ro',
           isa     => 'Num',
           default => 0,
           writer  => '_set_' . $_
) for qw[uploaded downloaded];
has infohash => (
    is  => 'ro',
    isa => subtype(
        as 'Str' => where { length $_ == 20 } => message {
            'Infohashes are 20 bytes in length';
        }
    ),
    init_arg => undef,
    lazy     => 1,
    default  => sub { sha1(bencode(shift->metadata->{info})) }
);
has metadata => (is         => 'ro',
                 isa        => 'HashRef',
                 init_arg   => undef,
                 lazy_build => 1
);

sub _build_metadata {
    my $s = shift;

    #return if ref $s ne __PACKAGE__;    # Applying roles makes deep rec
    open my $fh, '<', $s->path;
    sysread $fh, my $raw, -s $fh;
    my $metadata = bdecode $raw;
    $metadata;
}
sub name         { shift->metadata->{info}{name} }
sub pieces       { shift->metadata->{info}{pieces} }
sub piece_length { shift->metadata->{info}{'piece length'} }

sub piece_count {
    my $s     = shift;
    my $count = $s->size / $s->piece_length;
    int($count) + (($count == int $count) ? 1 : 0);
}
has basedir => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
    lazy     => 1,
    default  => sub { File::Spec->rel2abs(File::Spec->curdir) },
    trigger  => sub {
        my ($s, $n, $o) = @_;
        $o // return;
        $s->_clear_files;    # So they can be rebuilt with the new basedir
    }
);
has files => (is         => 'ro',
              isa        => 'ArrayRef[HashRef]',
              lazy_build => 1,
              init_arg   => undef,
              clearer    => '_clear_files'
);

sub _build_files {
    my $s = shift;
    defined $s->metadata->{info}{files} ?
        [
        map {
            {priority => 1,
             fh       => undef,
             mode     => 'c',
             length   => $_->{length},
             path =>
                 File::Spec->rel2abs(
                     File::Spec->catfile($s->basedir, $s->name, @{$_->{path}})
                 )
            }
            } @{$s->metadata->{info}{files}}
        ]
        : [
          {priority => 1,
           fh       => undef,
           mode     => 'c',
           length   => $s->metadata->{info}{length},
           path =>
               File::Spec->rel2abs(File::Spec->catfile($s->basedir, $s->name))
          }
        ];
}

sub size {
    my $s   = shift;
    my $ret = 0;
    $ret += $_->{length} for @{$s->files};
    $ret;
}

sub _open {
    my ($s, $i, $m) = @_;
    return 1 if $s->files->[$i]->{mode} eq $m;
    if (defined $s->files->[$i]->{fh}) {
        flock $s->files->[$i]->{fh}, LOCK_UN;
        close $s->files->[$i]->{fh};
        $s->files->[$i]->{fh} = ();
    }
    if ($m eq 'r') {
        sysopen($s->files->[$i]->{fh}, $s->files->[$i]->{path}, O_RDONLY)
            || return;
        flock($s->files->[$i]->{fh}, LOCK_SH) || return;
    }
    elsif ($m eq 'w') {
        my @split = File::Spec->splitdir($s->files->[$i]->{path});
        pop @split;    # File name itself
        my $dir = File::Spec->catdir(@split);
        File::Path::mkpath($dir) if !-d $dir;
        sysopen($s->files->[$i]->{fh},
                $s->files->[$i]->{path},
                O_WRONLY | O_CREAT)
            || return;
        flock $s->files->[$i]->{fh}, LOCK_EX;
        truncate $s->files->[$i]->{fh}, $s->files->[$i]->{length}
            if -s $s->files->[$i]->{fh}
                != $s->files->[$i]->{length};    # XXX - pre-allocate files
    }
    elsif ($m eq 'c') { }
    else              {return}
    return $s->files->[$i]->{mode} = $m;
}
has piece_cache => (is => 'ro', isa => 'HashRef', default => sub { {} });

sub _write_cache {
    my ($s, $f, $o, $d) = @_;
    my $path =
        File::Spec->catfile($s->basedir,
                            (scalar @{$s->files} == 1 ? () : $s->name),
                            '~ABPartFile_-'
                                . uc(
                                    substr(unpack('H*', $s->infohash), 0, 10))
                                . '.dat'
        );
    my @split = File::Spec->splitdir($path);
    pop @split;    # File name itself
    my $dir = File::Spec->catdir(@split);
    File::Path::mkpath($dir) if !-d $dir;
    sysopen(my ($fh), $path, O_WRONLY | O_CREAT)
        || return;
    flock $fh, LOCK_EX;
    my $pos = sysseek $fh, 0, SEEK_CUR;
    my $w = syswrite $fh, $d;
    flock $fh, LOCK_UN;
    close $fh;
    $s->piece_cache->{$f}{$o} = $pos;
    return $w;
}

sub _read_cache {
    my ($s, $f, $o, $l) = @_;
    $s->piece_cache->{$f} // return;
    $s->piece_cache->{$f}{$o} // return;
    my $path =
        File::Spec->catfile($s->basedir,
                            (scalar @{$s->files} == 1 ? () : $s->name),
                            '~ABPartFile_-'
                                . uc(
                                    substr(unpack('H*', $s->infohash), 0, 10))
                                . '.dat'
        );
    sysopen(my ($fh), $path, O_RDONLY)
        || return;
    flock $fh, LOCK_SH;
    sysseek $fh, $s->piece_cache->{$f}{$o}, SEEK_SET;
    my $w = sysread $fh, my ($d), $l;
    flock $fh, LOCK_UN;
    close $fh;
    return $d;
}

sub _read {
    my ($s, $index, $offset, $length) = @_;
    my $data         = '';
    my $file_index   = 0;
    my $total_offset = ($index * $s->piece_length) + $offset;
SEARCH:
    while ($total_offset > $s->files->[$file_index]->{length}) {
        $total_offset -= $s->files->[$file_index]->{length};
        $file_index++;
        last SEARCH    # XXX - return?
            if not defined $s->files->[$file_index]->{length};
    }
READ: while ((defined $length) && ($length > 0)) {
        my $this_read
            = (
              ($total_offset + $length) >= $s->files->[$file_index]->{length})
            ?
            ($s->files->[$file_index]->{length} - $total_offset)
            : $length;
        if (   (!-f $s->files->[$file_index]->{path})
            || (!$s->_open($file_index, 'r')))
        {   $data .= $s->_read_cache($file_index, $total_offset, $this_read)
                // ("\0" x $this_read);
        }
        else {
            sysseek $s->files->[$file_index]->{fh}, $total_offset, SEEK_SET;
            sysread $s->files->[$file_index]->{fh}, my ($_data), $this_read;
            $data .= $_data if $_data;
        }
        $file_index++;
        $length -= $this_read;
        last READ if not defined $s->files->[$file_index];
        $total_offset = 0;
    }
    return $data;
}

sub _write {
    my ($s, $index, $offset, $data) = @_;
    my $file_index = 0;
    my $total_offset = int(($index * $s->piece_length) + ($offset || 0));
SEARCH:
    while ($total_offset > $s->files->[$file_index]->{length}) {
        $total_offset -= $s->files->[$file_index]->{length};
        $file_index++;
        last SEARCH    # XXX - return?
            if not defined $s->files->[$file_index]->{length};
    }
WRITE: while ((defined $data) && (length $data > 0)) {
        my $this_write
            = (($total_offset + length $data)
               >= $s->files->[$file_index]->{length})
            ?
            ($s->files->[$file_index]->{length} - $total_offset)
            : length $data;
        if ($s->files->[$file_index]->{priority} == 0) {
            $s->_write_cache($file_index, $total_offset, substr $data, 0,
                             $this_write, '');
        }
        else {
            $s->_open($file_index, 'w') || die $!;
            sysseek $s->files->[$file_index]->{fh}, $total_offset, SEEK_SET;
            my $w = syswrite $s->files->[$file_index]->{fh}, substr $data, 0,
                $this_write, '';
        }
        $file_index++;
        last WRITE if not defined $s->files->[$file_index];
        $total_offset = 0;
    }
    return 1;
}

sub hashcheck (;@) {
    my $s = shift;
    my @indexes = @_ ? @_ : (0 .. $s->piece_count);
    $s->bitfield;    # Makes sure it's built
    for my $index (@indexes) {
        next if $index < 0 || $index > $s->piece_count;
        my $piece = $s->_read($index,
                              0,
                              $index == $s->piece_count
                              ?
                                  $s->size % $s->piece_length
                              : $s->piece_length
        );
        my $ok = defined($piece)
            && (substr($s->pieces, $index * 20, 20) eq sha1($piece));
        vec($s->{bitfield}, $index, 1) = $ok;
        $ok ?
            $s->_trigger_hash_pass($index)
            : $s->_trigger_hash_fail($index);
    }
}
has peers => (
    is      => 'ro',
    isa     => 'HashRef',
    lazy    => 1,
    clearer => '_clear_peers',
    builder => '_build_peers'

        # { handle            => AnyEvent::Handle
        #   peerid            => 'Str'
        #   reserved          => 'Str'
        #   bitfield          => 'Str'
        #   remote_choked     => 1
        #   remote_interested => 0
        #   remote_requests   => ArrayRef[ArrayRef] # List of [i, o, l]
        #   local_choked      => 1
        #   local_interested  => 0
        #   local_requests    => ArrayRef[ArrayRef] # List of [i, o, l]
        #   timeout           => AnyEvent::timer
        #   keepalive         => AnyEvent::timer
        #   local_allowed     => ArrayRef
        #   remote_allowed    => ArrayRef
        #   local_suggest     => ArrayRef
        #   remote_suggest    => ArrayRef
        # }
);
sub _build_peers { {} }

sub _add_peer {
    my ($s, $h) = @_;
    $s->{peers}{+$h} = {
        handle            => $h,
        peerid            => '',
        bitfield          => (pack 'b*', "\0" x $s->piece_count),
        remote_choked     => 1,
        remote_interested => 0,
        remote_requests   => [],
        local_choked      => 1,
        local_interested  => 0,
        local_requests    => [],
        timeout           => AE::timer(20, 0, sub { $s->_del_peer($h) }),
        keepalive         => AE::timer(
            30, 120,
            sub {
                $s->_send_encrypted($h, build_keepalive());
            }
        ),

        # BEP06
        local_allowed  => [],
        remote_allowed => [],
        local_suggest  => [],
        remote_suggest => [],

        #
        encryption => '?'
    };
}

sub _del_peer {
    my ($s, $h) = @_;
    $s->peers->{$h} // return;
    for my $req (@{$s->peers->{$h}{local_requests}}) {
        my ($i, $o, $l) = @$req;
        $s->working_pieces->{$i}{$o}[3] = ();
    }
    delete $s->peers->{$h};
    $h->destroy;
}
my $shuffle;
has trackers => (
    is       => 'ro',
    isa      => 'ArrayRef[HashRef]',
    lazy     => 1,
    required => 1,
    init_arg => undef,
    default  => sub {
        my $s = shift;
        $shuffle //= sub {
            my $deck = shift;    # $deck is a reference to an array
            return unless @$deck;    # must not be empty!
            my $i = @$deck;
            while (--$i) {
                my $j = int rand($i + 1);
                @$deck[$i, $j] = @$deck[$j, $i];
            }
        };
        my $trackers = [
            map {
                {urls       => $_,
                 complete   => 0,
                 incomplete => 0,
                 peers      => '',
                 peers6     => '',
                 ticker     => AE::timer(
                     1,
                     15 * 60,
                     sub {
                         return if $s->state eq 'stopped';
                         $s->announce('started');
                     }
                 ),
                 failures => 0
                }
                } defined $s->metadata->{announce}
            ? [$s->metadata->{announce}]
            : (),
            defined $s->metadata->{'announce-list'}
            ? @{$s->metadata->{'announce-list'}}
            : ()
        ];
        $shuffle->($trackers);
        $shuffle->($_->{urls}) for @$trackers;
        $trackers;
    }
);

sub announce {
    my ($s, $e) = @_;
    return if $a++ > 10;    # Retry attempts
    for my $tier (@{$s->trackers}) {
        $s->_announce_tier($e, $tier);
    }
}

sub _announce_tier {
    my ($s, $e, $tier) = @_;
    my @urls = grep {m[^https?://]} @{$tier->{urls}};
    return if $tier->{failures} > 5;
    return if $#{$tier->{urls}} < 0;                 # Empty tier?
    return if $tier->{urls}[0] !~ m[^https?://.+];
    local $AnyEvent::HTTP::USERAGENT
        = 'AnyEvent::BitTorrent/' . $AnyEvent::BitTorrent::VERSION;
    http_get $tier->{urls}[0] . '?info_hash=' . sub {
        local $_ = shift;
        s/([\W])/"%" . uc(sprintf("%2.2x",ord($1)))/eg;
        $_;
        }
        ->($s->infohash)
        . ('&peer_id=' . $s->peerid)
        . ('&uploaded=' . $s->uploaded)
        . ('&downloaded=' . $s->downloaded)
        . ('&left=' . $s->_left)
        . ('&port=' . $s->port)
        . '&compact=1'
        . ($e ? '&event=' . $e : ''), sub {
        my ($body, $hdr) = @_;
        if ($hdr->{Status} =~ /^2/) {
            my $reply = bdecode($body);
            if (defined $reply->{'failure reason'}) {    # XXX - Callback?
                push @{$tier->{urls}}, shift @{$tier->{urls}};
                $s->_announce_tier($e, $tier);
                $tier->{'failure reason'} = $reply->{'failure reason'};
                $tier->{failures}++;
            }
            else {                                       # XXX - Callback?
                $tier->{failures} = $tier->{'failure reason'} = 0;
                $tier->{peers}
                    = compact_ipv4(
                             uncompact_ipv4($tier->{peers} . $reply->{peers}))
                    if $reply->{peers};
                $tier->{peers6}
                    = compact_ipv6(
                           uncompact_ipv6($tier->{peers6} . $reply->{peers6}))
                    if $reply->{peers6};
                $tier->{complete}   = $reply->{complete};
                $tier->{incomplete} = $reply->{incomplete};
                $tier->{ticker} = AE::timer(
                    $reply->{interval} // (15 * 60),
                    $reply->{interval} // (15 * 60),
                    sub {
                        return if $s->state eq 'stopped';
                        $s->_announce_tier($e, $tier);
                    }
                );
            }
        }
        else {    # XXX - Callback?
            $tier->{'failure reason'}
                = "HTTP Error: $hdr->{Status} $hdr->{Reason}\n";
            $tier->{failures}++;
            push @{$tier->{urls}}, shift @{$tier->{urls}};
            $s->_announce_tier($e, $tier);
        }
        }
}
has _choke_timer => (
    is       => 'bare',
    isa      => 'Ref',
    init_arg => undef,
    required => 1,
    default  => sub {
        my $s = shift;
        AE::timer(
            15, 45,
            sub {
                return if $s->state ne 'active';
                my @interested
                    = grep { $_->{remote_interested} && $_->{remote_choked} }
                    values %{$s->peers};

                # XXX - Limit the number of upload slots
                for my $p (@interested) {
                    $p->{remote_choked} = 0;
                    $s->_send_encrypted($p->{handle}, build_unchoke());
                }

                # XXX - Send choke to random peer
            }
        );
    }
);
has _fill_requests_timer => (
    is       => 'bare',
    isa      => 'Ref',
    init_arg => undef,
    required => 1,
    default  => sub {
        my $s = shift;
        AE::timer(
            15, 1,
            sub {    # XXX - Limit by time/bandwidth
                return if $s->state ne 'active';
                my @waiting
                    = grep { defined && scalar @{$_->{remote_requests}} }
                    values %{$s->peers};
                return if !@waiting;
                my $total_sent = 0;
                while (@waiting && $total_sent < 2**20) {
                    my $p = splice(@waiting, rand @waiting, 1, ());
                    while ($total_sent < 2**20 && @{$p->{remote_requests}}) {
                        my $req = shift @{$p->{remote_requests}};

                        # XXX - If piece is bad locally
                        #          if remote supports fast ext
                        #             send reject
                        #          else
                        #             simply return
                        #       else...
                        $s->_send_encrypted(
                                $p->{handle},
                                build_piece(
                                    $req->[0], $req->[1],
                                    $s->_read($req->[0], $req->[1], $req->[2])
                                )
                        );
                        $total_sent += $req->[2];
                    }
                }
                $s->_set_uploaded($s->uploaded + $total_sent);
            }
        );
    }
);
has _peer_timer => (is       => 'ro',
                    isa      => 'Ref',
                    init_arg => undef,
                    lazy     => 1,
                    clearer  => '_clear_peer_timer',
                    builder  => '_build_peer_timer'
);

sub _build_peer_timer {
    my $s = shift;
    AE::timer(
        1, 15,
        sub {
            return if !$s->_left;

            # XXX - Initiate connections when we are in Super seed mode?
            my @cache = map {
                $_->{peers} ? uncompact_ipv4($_->{peers}) : (),
                    $_->{peers6} ?
                    uncompact_ipv6($_->{peers6})
                    : ()
            } @{$s->trackers};
            return if !@cache;
            for my $i (1 .. @cache) {
                last if $i > 10;    # XXX - Max half open
                last
                    if scalar(keys %{$s->peers}) > 100;    # XXX - Max peers
                my $addr = splice @cache, rand $#cache, 1;
                my $handle;
                $handle = AnyEvent::Handle->new(
                    connect    => $addr,
                    on_prepare => sub {60},
                    on_error   => sub {
                        my ($hdl, $fatal, $msg) = @_;

                        # XXX - callback
                        #AE::log error => "got error $msg\n";
                        $s->_del_peer($hdl);
                    },
                    on_connect_error => sub {
                        my ($hdl, $fatal, $msg) = @_;
                        $s->_del_peer($hdl);

                        # XXX - callback
                        #AE::log
                        #    error => sprintf "%sfatal error (%s)\n",
                        #    $fatal ? '' : 'non-',
                        #    $msg // 'Connection timed out';
                        return if !$fatal;
                    },
                    on_connect => sub {
                        my ($h, $host, $port, $retry) = @_;
                        $s->_add_peer($handle);
                        $s->_send_handshake($handle);
                    },
                    on_eof => sub {
                        my $h = shift;
                        $s->_del_peer($h);
                    },
                    on_read => sub { $s->_on_read(@_) }
                );
            }
        }
    );
}

sub _on_read_incoming {
    my ($s, $h) = @_;
    $h->rbuf // return;

    # XXX - Handle things if the stream is encrypted
    my $packet = parse_packet(\$h->rbuf);
    return if !$packet;
    if (defined $packet->{error}) {
        return $s->_del_peer($h);
    }
    elsif ($packet->{type} == $HANDSHAKE) {
        ref $packet->{payload} // return;
        $s->peers->{$h}{reserved} = $packet->{payload}[0];
        return $s->_del_peer($h)
            if $packet->{payload}[1] ne $s->infohash;
        $s->peers->{$h}{peerid} = $packet->{payload}[2];
        $s->_send_handshake($h);
        $s->_send_bitfield($h);
        $s->peers->{$h}{timeout}
            = AE::timer(60, 0, sub { $s->_del_peer($h) });
        $s->peers->{$h}{bitfield} = pack 'b*', (0 x $s->piece_count);
        $h->on_read(sub { $s->_on_read(@_) });
    }
    else {    # This should never happen
    }
    1;
}

sub _on_read {
    my ($s, $h) = @_;
    while (my $packet = parse_packet(\$h->rbuf)) {
        if (defined $packet->{error}) {
            $s->_del_peer($h);
            return;
        }
        elsif ($packet->{type} eq $KEEPALIVE) {

            # Do nothing!
        }
        elsif ($packet->{type} == $HANDSHAKE) {
            ref $packet->{payload} // return;
            $s->peers->{$h}{reserved} = $packet->{payload}[0];
            return $s->_del_peer($h)
                if $packet->{payload}[1] ne $s->infohash;
            $s->peers->{$h}{peerid} = $packet->{payload}[2];
            $s->_send_bitfield($h);
            $s->peers->{$h}{timeout}
                = AE::timer(60, 0, sub { $s->_del_peer($h) });
            $s->peers->{$h}{bitfield} = pack 'b*', (0 x $s->piece_count);
        }
        elsif ($packet->{type} == $INTERESTED) {
            $s->peers->{$h}{remote_interested} = 1;
        }
        elsif ($packet->{type} == $NOT_INTERESTED) {
            $s->peers->{$h}{remote_interested} = 0;

            # XXX - Clear any requests in queue
            # XXX - Send choke just to be sure
        }
        elsif ($packet->{type} == $CHOKE) {
            $s->peers->{$h}{local_choked} = 1;
            if (!(vec($s->peers->{$h}{reserved}, 7, 1) & 0x04)) {
                for my $req (@{$s->peers->{$h}{local_requests}}) {
                    $s->working_pieces->{$req->[0]}{$req->[1]}[3] = ()
                        unless
                        defined $s->working_pieces->{$req->[0]}{$req->[1]}[4];
                }
            }
            $s->_consider_peer($s->peers->{$h});
        }
        elsif ($packet->{type} == $UNCHOKE) {
            $s->peers->{$h}{local_choked} = 0;
            $s->peers->{$h}{timeout}
                = AE::timer(120, 0, sub { $s->_del_peer($h) });
            $s->_request_pieces($s->peers->{$h});
        }
        elsif ($packet->{type} == $HAVE) {
            vec($s->peers->{$h}{bitfield}, $packet->{payload}, 1) = 1;
            $s->_consider_peer($s->peers->{$h});
            $s->peers->{$h}{timeout}
                = AE::timer(60, 0, sub { $s->_del_peer($h) });
        }
        elsif ($packet->{type} == $BITFIELD) {
            $s->peers->{$h}{bitfield} = $packet->{payload};
            $s->_consider_peer($s->peers->{$h});
        }
        elsif ($packet->{type} == $REQUEST) {
            $s->peers->{$h}{timeout}
                = AE::timer(120, 0, sub { $s->_del_peer($h) });

            # XXX - Make sure (index + offset + length) < $s->size
            #       if not, send reject if remote supports fast ext
            #       either way, ignore the request
            push @{$s->peers->{$h}{remote_requests}}, $packet->{payload};
        }
        elsif ($packet->{type} == $PIECE) {
            $s->peers->{$h}{timeout}
                = AE::timer(120, 0, sub { $s->_del_peer($h) });
            my ($index, $offset, $data) = @{$packet->{payload}};

            # Make sure $index is a working piece
            $s->working_pieces->{$index} // return;

            # Make sure we req from this peer
            return
                if !grep {
                       $_->[0] == $index
                    && $_->[1] == $offset
                    && $_->[2] == length $data
                } @{$s->peers->{$h}{local_requests}};
            $s->peers->{$h}{local_requests} = [
                grep {
                           ($_->[0] != $index)
                        || ($_->[1] != $offset)
                        || ($_->[2] != length($data))
                    } @{$s->peers->{$h}{local_requests}}
            ];
            $s->working_pieces->{$index}{$offset}[4] = $data;
            $s->working_pieces->{$index}{$offset}[5] = ();
            $s->_set_downloaded($s->downloaded + length $data);
            if (0 == scalar grep { !defined $_->[4] }
                values %{$s->working_pieces->{$index}})
            {   my $piece = join '',
                    map  { $s->working_pieces->{$index}{$_}[4] }
                    sort { $a <=> $b }
                    keys %{$s->working_pieces->{$index}};
                if ((substr($s->pieces, $index * 20, 20) eq sha1($piece))) {
                    for my $attempt (1 .. 5) {   # XXX = 5 == failure callback
                        last
                            if $s->_write($index, 0, $piece) == length $piece;
                    }
                    vec($s->{bitfield}, $index, 1) = 1;
                    $s->_broadcast(
                        build_have($index),
                        sub {
                            !!!index substr(unpack('b*', $_->{bitfield}),
                                            0, $s->piece_count + 1),
                                0, 0;
                        }
                    );
                    $s->announce('complete')
                        if !scalar grep {$_} split '',
                        substr unpack('b*', ~$s->bitfield), 0,
                        $s->piece_count + 1;
                    $s->_consider_peer($_)
                        for grep { $_->{local_interested} }
                        values %{$s->peers};
                    $s->_trigger_hash_pass($index);
                }
                else {
                    $s->_trigger_hash_fail($index);

                    # XXX - Not sure what to do... I'd
                    #       ban the peers involved and
                    #       try the same piece again.
                }
                delete $s->working_pieces->{$index};
            }
            $s->_request_pieces($s->peers->{$h});
        }
        elsif ($packet->{type} == $CANCEL) {
            my ($index, $offset, $length) = @{$packet->{payload}};
            return    # XXX - error callback if this block is not in the queue
                if !grep {
                       $_->[0] == $index
                    && $_->[1] == $offset
                    && $_->[2] == $length
                } @{$s->peers->{$h}{remote_requests}};
            $s->peers->{$h}{remote_requests} = [
                grep {
                           ($_->[0] != $index)
                        || ($_->[1] != $offset)
                        || ($_->[2] != $length)
                    } @{$s->peers->{$h}{remote_requests}}
            ];
        }
        elsif ($packet->{type} == $PORT) {

            # Do nothing... as we don't have a DHT node. Yet?
        }
        elsif ($packet->{type} == $SUGGEST) {
            push @{$s->peers->{$h}{local_suggest}}, $packet->{payload};
        }
        elsif ($packet->{type} == $HAVE_ALL) {
            $s->peers->{$h}{bitfield} = pack 'b*', (1 x $s->piece_count);
            $s->_consider_peer($s->peers->{$h});
            $s->peers->{$h}{timeout}
                = AE::timer(120, 0, sub { $s->_del_peer($h) });
        }
        elsif ($packet->{type} == $HAVE_NONE) {
            $s->peers->{$h}{bitfield} = pack 'b*', (0 x $s->piece_count);
            $s->peers->{$h}{timeout}
                = AE::timer(30, 0, sub { $s->_del_peer($h) });
        }
        elsif ($packet->{type} == $REJECT) {
            my ($index, $offset, $length) = @{$packet->{payload}};
            return    # XXX - error callback if this block is not in the queue
                if !grep {
                       $_->[0] == $index
                    && $_->[1] == $offset
                    && $_->[2] == $length
                } @{$s->peers->{$h}{local_requests}};
            $s->working_pieces->{$index}{$offset}->[3] = ();
            $s->peers->{$h}{local_requests} = [
                grep {
                           ($_->[0] != $index)
                        || ($_->[1] != $offset)
                        || ($_->[2] != $length)
                    } @{$s->peers->{$h}{local_requests}}
            ];
            $s->peers->{$h}{timeout}
                = AE::timer(30, 0, sub { $s->_del_peer($h) });
        }
        elsif ($packet->{type} == $ALLOWED_FAST) {
            push @{$s->peers->{$h}{local_allowed}}, $packet->{payload};
        }
        else {

            # use Data::Dump qw[pp];
            # die 'Unhandled packet: ' . pp $packet;
        }
        last
            if 5 > length($h->rbuf // '');    # Min size for protocol
    }
}

sub _send_bitfield {
    my ($s, $h) = @_;
    if (vec($s->peers->{$h}{reserved}, 7, 1) & 0x04) {
        if ($s->seed) {
            return $s->_send_encrypted($h, build_haveall());
        }
        elsif ($s->bitfield() !~ m[[^\0]]) {
            return $s->_send_encrypted($h, build_havenone());
        }
    }

    # XXX - If it's cheaper to send HAVE packets than a full BITFIELD, do it
    $s->_send_encrypted($h, build_bitfield($s->bitfield));
}

sub _broadcast {
    my ($s, $data, $qualifier) = @_;
    $qualifier //= sub {1};
    $s->_send_encrypted($_->{handle}, $data)
        for grep { $qualifier->() } values %{$s->peers};
}

sub _consider_peer {    # Figure out whether or not we find a peer interesting
    my ($s, $p) = @_;
    return if $s->state ne 'active';
    return if $s->complete;
    my $relevence = $p->{bitfield} & $s->wanted;
    my $interesting
        = (
         index(substr(unpack('b*', $relevence), 0, $s->piece_count + 1), 1, 0)
             != -1) ? 1 : 0;
    if ($interesting) {
        if (!$p->{local_interested}) {
            $p->{local_interested} = 1;
            $s->_send_encrypted($p->{handle}, build_interested());
        }
    }
    else {
        if ($p->{local_interested}) {
            $p->{local_interested} = 0;
            $s->_send_encrypted($p->{handle}, build_not_interested());
        }
    }
}
has working_pieces => (is       => 'ro',
                       isa      => 'HashRef',
                       lazy     => 1,
                       init_arg => undef,
                       default  => sub { {} }
);

sub _file_to_range {
    my ($s, $file) = @_;
    my $start = 0;
    for (0 .. $file - 1) {
        $start += $s->files->[$_]->{length};
    }
    my $end = $start + $s->files->[$file]->{length};
    $start = $start / $s->piece_length;
    $end   = $end / $s->piece_length;
    (int($start) .. int $end + ($end != int($end) ? 0 : +1));
}

sub _request_pieces {
    my ($s, $p) = @_;
    return if $s->state ne 'active';
    use Scalar::Util qw[weaken];
    weaken $p;
    $p // return;
    $p->{handle} // return;
    my @indexes;
    if (scalar keys %{$s->working_pieces} < 10) {   # XXX - Max working pieces

        for my $findex (0 .. $#{$s->files}) {
            for my $index ($s->_file_to_range($findex)) {
                push @indexes, map {
                    vec($p->{bitfield}, $index, 1)
                        && !vec($s->bitfield, $index, 1) ?
                        $index
                        : ()
                } 1 .. $s->{files}[$findex]{priority};
            }
        }
    }
    else {
        @indexes = keys %{$s->working_pieces};
    }
    return if !@indexes;
    my $index = $indexes[rand @indexes];  # XXX - Weighted random/Rarest first
    my $piece_size
        = $index == $s->piece_count ?
        $s->size % $s->piece_length
        : $s->piece_length;
    my $block_count = $piece_size / $block_size;
    my @offsets = map { $_ * $block_size }
        0 .. $block_count - ((int($block_count) == $block_count) ? 1 : 0);
    $s->working_pieces->{$index} //= {map { $_ => undef } @offsets};
    my @unrequested = sort { $a <=> $b }
        grep {    # XXX - If there are no unrequested blocks, pick a new index
        (!ref $s->working_pieces->{$index}{$_})
            || (   (!defined $s->working_pieces->{$index}{$_}[4])
                && (!defined $s->working_pieces->{$index}{$_}[3]))
        } @offsets;
    for (scalar @{$p->{local_requests}} .. 12) {
        my $offset = shift @unrequested;
        $offset // return;    # XXX - Start working on another piece
        my $_block_size
            = ($index == $s->piece_count && ($offset == $offsets[-1]))
            ?
            $piece_size % $block_size
            : $block_size;

        # XXX - Limit to x req per peer (future: based on bandwidth)
        #warn sprintf 'Requesting %d, %d, %d', $index, $offset, $_block_size;
        $s->_send_encrypted($p->{handle},
                            build_request($index, $offset, $_block_size))
            ;                 # XXX - len for last piece
        $s->working_pieces->{$index}{$offset} = [
            $index, $offset,
            $_block_size,
            $p,     undef,
            AE::timer(
                60, 0,
                sub {
                    $p // return;
                    $p->{handle} // return;
                    $s->_send_encrypted($p->{handle},
                                 build_cancel($index, $offset, $_block_size));
                    $s->working_pieces->{$index}{$offset}[3] = ();
                    $p->{local_requests} = [
                        grep {
                                   $_->[0] != $index
                                || $_->[1] != $offset
                                || $_->[2] != $_block_size
                            } @{$p->{local_requests}}
                    ];
                    $p->{timeout} = AE::timer(45, 0,
                                         sub { $s->_del_peer($p->{handle}) });

                    #$s->_request_pieces( $p) #  XXX - Ask a different peer
                }
            )
        ];
        weaken($s->working_pieces->{$index}{$offset}[3]);
        push @{$p->{local_requests}}, [$index, $offset, $_block_size];
    }
}

# Cheap callback system
has on_hash_pass => (
    isa     => 'CodeRef',
    is      => 'rw',
    default => sub {
        sub { !!1 }
    },
    clearer => '_no_hash_pass'
);
sub _trigger_hash_pass { shift->on_hash_pass()->(@_) }
has on_hash_fail => (
    isa     => 'CodeRef',
    is      => 'rw',
    default => sub {
        sub { !!1 }
    },
    clearer => '_no_hash_fail'
);
sub _trigger_hash_fail { shift->on_hash_fail()->(@_) }

#
has state => (is      => 'ro',
              isa     => enum([qw[active stopped paused]]),
              writer  => '_set_state',
              default => 'active'
);

sub stop {
    my $s = shift;
    return if $s->state eq 'stopped';
    $s->announce('stopped');
    $s->_clear_peers;
    $s->_clear_peer_timer;
    $s->_open($_, 'c') for 0 .. $#{$s->files};
    $s->_set_state('stopped');
}

sub start {
    my $s = shift;
    $s->announce('started') unless $s->state eq 'active';
    $s->peers;
    $s->_peer_timer;
    $s->_set_state('active');
}

sub pause {
    my $s = shift;
    $s->peers;
    $s->_peer_timer;
    $s->_set_state('paused');
}

#
sub BUILD {
    my ($s, $a) = @_;
    $s->start  if $s->state eq 'active';
    $s->paused if $s->state eq 'paused';
}

# Testing stuff goes here
sub _send_encrypted {
    my ($s, $h, $packet) = @_;

    # XXX - Currently doesn't do anything and may never do anything
    return $h->push_write($packet);
}

sub _send_handshake {
    my ($s, $h) = @_;

    # XXX - Send encrypted handshake if encryption status is unknown or true
    $h->push_write(build_handshake($s->reserved, $s->infohash, $s->peerid));
}

# Wrap everything up
__PACKAGE__->meta->make_immutable();
no Any::Moose;
no Any::Moose '::Util::TypeConstraints';
1;

=pod

=head1 NAME

AnyEvent::BitTorrent - Yet Another BitTorrent Client Module

=head1 Synopsis

    use AnyEvent::BitTorrent;
    my $client = AnyEvent::BitTorrent->new( path => 'some.torrent' );
    AE::cv->recv;

=head1 Description

This is a painfully simple BitTorrent client written on a whim that implements
the absolute basics. For a full list of what's currently supported, what you
will likely find in a future version, and what you'll never get from this, see
the section entitled "L<This Module is Lame!|/"This Module is Lame!">"

=head1 Methods

The API, much like the module itself, is simple.

Anything you find by skimming the source is likely not ready for public use
and will be subject to change before C<v1.0.0>. Here's the public interface as
of this version:

=head2 C<new( ... )>

    my $c = AnyEvent::BitTorrent->(
        path         => 'some/legal.torrent',
        basedir      => './storage/',
        port         => 6881,
        on_hash_pass => sub { ... },
        on_hash_fail => sub { ... },
        state        => 'stopped',
        piece_cache  => $quick_restore
    );

This constructor understands the following arguments:

=over

=item C<path>

This is the only required parameter. It's the path to a valid .torrent file.

=item C<basedir>

This is the base directory all data will be stored in and/or read from.
Multifile torrents will create another directory below this to store all
files.

By default, this is the current working directory when
L<C<new( ... )>|/"new( ... )"> is called.

=item C<port>

This is the preferred port local host binds and expects incoming peers to
connect to.

By default, this is a zero; the system will pick a port number randomly.

=item C<on_hash_fail>

This is a subroutine called whenever a piece fails to pass
L<hashcheck|/"hashcheck( [...] )">. The callback is handed the piece's index.

=item C<on_hash_pass>

This is a subroutine called whenever a piece passes its
L<hashcheck|/"hashcheck( [...] )">. The callback is handed the piece's index.

=item C<state>

This must be one of the following:

=over

=item C<started>

This is the default. The client will attempt to create new connections, make
and fill requests, etc. This is normal client behavior.

=item C<paused>

In this state, connections will be made and accepted but no piece requests
will be made or filled. To resume full, normal behavior, you must call
L<C<start( )>|/"start( )">.

=item C<stopped>

Everything is put on hold. No new outgoing connections are attempted and
incoming connections are rejected. To resume full, normal behavior, you must
call L<C<start( )>|/"start( )">.

=back

=item C<piece_cache>

This is the index list returned by L<C<piece_cache( )>|/"piece_cache( )"> in a
previous instance. Using this should make a complete resume system a trivial
task.

=back

=head2 C<hashcheck( [...] )>

This method expects...

=over

=item ...a list of integers. You could use this to check a range of pieces (a
single file, for example).

    $client->hashcheck( 1 .. 5, 34 .. 56 );

=item ...a single integer. Only that specific piece is checked.

    $client->hashcheck( 17 );

=item ...nothing. All data related to this torrent will be checked.

    $client->hashcheck( );

=back

As pieces pass or fail, your C<on_hash_pass> and C<on_hash_fail> callbacks are
triggered.

=head2 C<start( )>

Sends a 'started' event to trackers and starts performing as a client is
expected. New connections are made and accepted, requests are made and filled,
etc.

=head2 C<stop( )>

Sends a stopped event to trackers, closes all connections, stops attempting
new outgoing connections, rejects incoming connections and closes all open
files.

=head2 C<pause( )>

The client remains mostly active; new connections will be made and accepted,
etc. but no requests will be made or filled while the client is paused.

=head2 C<infohash( )>

Returns the 20-byte SHA1 hash of the value of the info key from the metadata
file.

=head2 C<peerid( )>

Returns the 20 byte string used to identify the client. Please see the
L<spec|/"PeerID Specification"> below.

=head2 C<port( )>

Returns the port number the client is listening on.

=head2 C<size( )>

Returns the total size of all L<files|/"files( )"> described in the torrent's
metadata.

Note that this value is recalculated every time you call this method. If you
need it more than occasionally, it may be best to cache it yourself.

=head2 C<name( )>

Returns the UTF-8 encoded string the metadata suggests we save the file (or
directory, in the case of multi-file torrents) under.

=head2 C<uploaded( )>

Returns the total amount uploaded to remote peers.

=head2 C<downloaded( )>

Returns the total amount downloaded from other peers.

=head2 C<left( )>

Returns the approximate amount based on the pieces we still
L<want|/"wanted( )"> multiplied by the L<size of pieces|/"piece_length( )">.

=head2 C<piece_length( )>

Returns the number of bytes in each piece the file or files are split into.
For the purposes of transfer, files are split into fixed-size pieces which are
all the same length except for possibly the last one which may be truncated.

=head2 C<bitfield( )>

Returns a packed binary string in ascending order (ready for C<vec()>). Each
index that the client has is set to one and the rest are set to zero.

=head2 C<wanted( )>

Returns a packed binary string in ascending order (ready for C<vec()>). Each
index that the client has or simply does not want is set to zero and the rest
are set to one.

This value is calculated every time the method is called. Keep that in mind.

=head2 C<complete( )>

Returns true if we have downloaded everything we L<wanted|/"wanted( )"> which
is not to say that we have all data and can L<seed|/"seed( )">.

=head2 C<seed( )>

Returns true if we have all data related to the torrent.

=head2 C<files( )>

Returns a list of hash references with the following keys:

=over

=item C<length>

Which is the size of file in bytes.

=item C<path>

Which is the absolute path of the file.

=item C<priority>

Download priority for this file. By default, all files have a priority of
C<1>. There is no built in scale; the higher the priority, the better odds a
piece from it will be downloaded first. Setting a file's priority to C<1000>
while the rest are still at C<1> will likely force the file to complete before
any other file is started.

We do not download files with a priority of zero.

=back

=head2 C<peers( )>

Returns the list of currently connected peers. The organization of these peers
is not yet final so... don't write anything you don't expect to break before
we hit C<v1.0.0>.

=head2 C<state( )>

Returns C<active> if the client is L<started|/"start( )">, C<paused> if client
is L<paused|/"pause( )">, and C<stopped> if the client is currently
L<stopped|/"stop( )">.

=head2 C<piece_cache( )>

Pieces which overlap files with zero priority are stored in a part file which
is indexed internally. To save this index (for resume, etc.) store the values
returned by this method and pass it to L<new( )|/"new( ... )">.

=head2 C<trackers( )>

Returns a list of hashes, each representing a single tier of trackers as
defined by L<BEP12|Net::BitTorrent::Protocol::BEP12>. The hashes contain the
following keys:

=over

=item C<complete>

The is a count of complete peers (seeds) as returned by the most recent
announce.

=item C<failures>

This is a running total of the number of failed announces we've had in a row.
This value is reset when we have a successful announce.

=item C<incomplete>

The is a count of incomplete peers (leechers) as returned by the most recent
announce.

=item C<peers>

Which is a compact collection of IPv4 peers returned by the tracker. See
L<BEP23|Net::BitTorrent::Protocol::BEP23>.

=item C<peers6>

Which is a compact collection of IPv6 peers returned by the tracker. See
L<BEP07|Net::BitTorrent::Protocol::BEP07>.

=item C<urls>

Which is a list of URLs.

=back

=head1 This Module is Lame!

Yeah, I said it.

There are a few things a BitTorrent client must implement (to some degree) in
order to interact with other clients in a modern day swarm.
L<AnyEvent::BitTorrent|AnyEvent::BitTorrent> is meant to meet that bare
minimum but it's based on L<Moose|Moose> or L<Mouse|Mouse> so you could always
subclass it to add more advanced functionality. Hint, hint!

=head2 What is currently supported?

Basic stuff. We can make and handle piece requests. Deal with cancels,
disconnect idle peers, unchoke folks, fast extensions, file download
priorities. Normal... stuff. HTTP trackers.

=head2 What will probably be supported in the future?

DHT (which will likely be in a separate dist), IPv6 stuff... I'll get around
to those.

Long term, UDP trackers may be supported.

For a detailed list, see the TODO file included with this distribution.

=head2 What will likely never be supported?

We can't have nice things. Protocol encryption, uTP, endgame tricks, ...these
will probably never be included in L<AnyEvent::BitTorrent>.

=head2 What should I use instead?

If you're reading all of this with a scowl, there are many alternatives to
this module, most of which are sure to be better suited for advanced users. I
suggest (in no particular order):

=over

=item L<BitFlu|http://bitflu.workaround.ch/>. It's written in Perl but you'll
still need to be on a Linux, *BSD, et al. system to use it.

=item L<Net::BitTorrent> ...in the future. I I<do not> suggest using either
the current stable or unstable versions found on CPAN. The next version is
being worked on and will be based on L<Reflex|Reflex>.

=back

If you're working on a Perl based client and would like me to link to it, send
a bug report to the tracker L<listed below|/"Bug Reports">.

=head1 Subclassing AnyEvent::BitTorrent

TODO

If you subclass this module and change the way it functions to that which in
any way proves harmful to individual peers or the swarm at large, rather than
damage L<AnyEvent::BitTorrent>'s reputation, override the peerid attribute.
Thanks.

=head1 PeerID Specification

L<AnyEvent::BitTorrent> may be identified in a swarm by its peer id. As of
this version, our peer id is in 'Azureus style' with a single digit for the
Major version, two digits for the minor version, and a single character to
indicate stability (stable releases marked with C<S>, unstable releases marked
with C<U>). It looks sorta like:

    -AB110S-  Stable v1.10.0 relese (typically found on CPAN, tagged in repo)
    -AB110U-  Unstable v1.10.X release (private builds, early testing, etc.)

=head1 Bug Reports

If email is better for you, L<my address is mentioned below|/"Author"> but I
would rather have bugs sent through the issue tracker found at
http://github.com/sanko/anyevent-bittorrent/issues.

Please check the ToDo file included with this distribution in case your bug
is already known (...I probably won't file bug reports to myself).

=head1 See Also

L<Net::BitTorrent::Protocol> - The package which does all of the wire protocol
level heavy lifting.

=head1 Author

Sanko Robinson <sanko@cpan.org> - http://sankorobinson.com/

CPAN ID: SANKO

=head1 License and Legal

Copyright (C) 2011-2012 by Sanko Robinson <sanko@cpan.org>

This program is free software; you can redistribute it and/or modify it under
the terms of
L<The Artistic License 2.0|http://www.perlfoundation.org/artistic_license_2_0>.
See the F<LICENSE> file included with this distribution or
L<notes on the Artistic License 2.0|http://www.perlfoundation.org/artistic_2_0_notes>
for clarification.

When separated from the distribution, all original POD documentation is
covered by the
L<Creative Commons Attribution-Share Alike 3.0 License|http://creativecommons.org/licenses/by-sa/3.0/us/legalcode>.
See the
L<clarification of the CCA-SA3.0|http://creativecommons.org/licenses/by-sa/3.0/us/>.

Neither this module nor the L<Author|/Author> is affiliated with BitTorrent,
Inc.

=cut
