#!/usr/bin/perl
# CIVITAS
#
# This script creates a directory on this host
use strict;
use warnings;

sub usage {
    print <<USAGE;
usage: createDir.pl dir
    Create the directory dir on the current host.
USAGE
    exit;
}
if ( $#ARGV == 0 ) {

    # create the directory on this host
    my ($reqDir) = $ARGV[0];
    my @rdirs = split( /\//, $reqDir );
    $reqDir = "";
    foreach my $d (@rdirs) {
        $reqDir = $reqDir . $d . '/';
        if ( !( -e $reqDir ) ) {
            die("$!") unless mkdir($reqDir);
        }
    }
}
else {
    print $#ARGV . "\n";
    usage();
}
