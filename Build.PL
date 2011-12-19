#!/usr/bin/perl -w
use strict;
use warnings;
use File::Find;
use Module::Build;
my $automated_testing = $ENV{'AUTOMATED_TESTING'}
    || $ENV{'PERL_MM_USE_DEFAULT'};
my $is_developer = ((-d '.git') ? 1 : 0) or ($ENV{'RELEASE_TESTING'} ? 1 : 0);
my @tests;
find \&find_cb, qw[t/];
my $mb
    = ($is_developer
       && require './_dev/Builder.pm' ? ('_dev::Builder') : 'Module::Build')
    ->new(
       module_name => 'AnyEvent::BitTorrent',
       license     => 'artistic_2',
       dist_author => 'Sanko Robinson <sanko@cpan.org>',
       requires    => {
                    'Any::Moose'                => 0,
                    'AnyEvent'                  => 0,
                    'AnyEvent::HTTP'            => 0,
                    'AnyEvent::Handle'          => 0,
                    'AnyEvent::Socket'          => 0,
                    'Digest::SHA'               => 0,
                    Carp                        => 0,
                    Exporter                    => 0,
                    Fcntl                       => 0,
                    'File::Path'                => 0,
                    'File::Spec'                => 0,
                    'Module::Build'             => 0.38,
                    'Net::BitTorrent::Protocol' => '0.9.1',
                    'Scalar::Util'              => 0,
                    perl                        => '5.10.0'
       },
       build_requires => {'Module::Build' => 0.38,
                          perl            => '5.10.0',
                          'Test::More'    => 0,
                          'File::Temp'    => 0
       },
       configure_requires => {'File::Find'    => 0,
                              'Module::Build' => 0.38
       },
       test_files     => \@tests,
       test_file_exts => ['.t'],
       meta_merge     => {
           keywords  => [qw[BitTorrent AnyEvent]],
           resources => {
               bugtracker =>
                   'http://github.com/sanko/anyevent-bittorrent/issues',
               repository => 'git://github.com/sanko/anyevent-bittorrent.git',
               ChangeLog =>
                   'http://github.com/sanko/anyevent-bittorrent/commits/'
           }
       },
       create_readme => 1
    );
$mb->notes(automated_testing => $automated_testing ? 1 : 0);
$mb->notes(release_testing   => $is_developer);
$mb->notes(test_suite        => \@tests);
$mb->notes(gmtime            => gmtime);
$mb->notes(verbose => scalar grep {m[^v$]} keys %{$mb->args()});
$mb->create_build_script;
exit 0;

sub find_cb {
    return if -d $_ or -l $_;
    return unless -T $_;
    return unless $_ =~ m[.+\.t$];
    return push @tests, $File::Find::name;
}
__END__
Copyright (C) 2008-2012 by Sanko Robinson <sanko@cpan.org>

This program is free software; you can redistribute it and/or modify it
under the terms of The Artistic License 2.0.  See the LICENSE file
included with this distribution or
http://www.perlfoundation.org/artistic_license_2_0.  For
clarification, see http://www.perlfoundation.org/artistic_2_0_notes.

When separated from the distribution, all POD documentation is covered by
the Creative Commons Attribution-Share Alike 3.0 License.  See
http://creativecommons.org/licenses/by-sa/3.0/us/legalcode.  For
clarification, see http://creativecommons.org/licenses/by-sa/3.0/us/.
