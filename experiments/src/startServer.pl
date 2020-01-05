#!/usr/bin/perl
# CIVITAS
#
# This script starts a server. It may be a tabulation teller,
# a registration teller, or a bulletin board.

use FindBin;                # where is this script installed?
use lib $FindBin::Bin;      # include this directory in the library search path
use Civitas::Experiments;
use strict;
use warnings;

sub usage {
    print <<USAGE;
usage: startServer.pl file.exp kind host port pubKey privKey log
    Start server listening on the given port using the given public
    and private keys.

    file.exp is the experiment description file, and provides details
    of where the service should store files and logs.

    The argument 'kind' should be one of tab, reg, or bb, for
    tabulation teller, registration teller, or bulletin board (ballot box)
    respectively.

    If host is "localhost" then the service will be started locally.
    Otherwise, the script will attempt to ssh to host, and start the
    service.

    The service will respond to requests sent on port port.

    pubKey and privKey are the public key file and private key file for the
    service respectively.

    If log is defined, and kind is bb, then the bulletin board/ballot box
    will produce a log.
USAGE
    exit;
}
if ( $#ARGV != 5 && $#ARGV != 6) {
    print $#ARGV . "\n";
    usage();
}
my ( $expDesc, $kind, $host, $port, $pubKeyFile, $privKeyFile, $log ) = @ARGV;
initExp($expDesc);
my %progName = (
                 "tab" => 'civitas.tabulation.server.ThreadAwareTabTeller',
                 "reg" => 'civitas.registration.server.RegTeller',
                 "bb"  => 'civitas.bboard.server.GenericBBS',
);
if ( !( exists $progName{$kind} ) ) {
    print "Error: unknown kind '$kind'\n";
    usage();
}
my $prog      = $progName{$kind};
my @extraPreArgs = ();
my @extraPostArgs = ();
my @jvmArgs = ();
if ( $kind eq 'bb' ) {
    push( @extraPreArgs, BBFileRoot( $host, $port ) );
    if (defined $log && length($log) > 0) {
        my $logfile = experimentTempResultsDir("log", "bb", $host, $port);
        push( @extraPostArgs, "-log $logfile");
    }
}
elsif ( $kind eq 'tab' ) {
    push( @extraPreArgs, TabFileRoot($host, $port), FileCacheRoot( $host, $port ) );
    push( @extraPostArgs, $port + 10000 );
}
elsif ( $kind eq 'reg' ) {
    push( @extraPreArgs, FileCacheRoot( $host, $port ) );
    push( @extraPostArgs, $port + 10000 );
}

if ($recordMemoryUsageFlag) {
    my $loggcfile = experimentTempResultsDir("loggc", $kind, $host, $port);
    push(@jvmArgs, "-j");
    push(@jvmArgs, "-Xloggc:$loggcfile");
}

debugprint "Start $kind server on host $host port $port\n";
my @prog = ( "$CIVITAS/bin/civitasrun", @jvmArgs, $prog, @extraPreArgs, $port, $pubKeyFile, $privKeyFile, @extraPostArgs );
if ( length($timeCmd) > 0 ) {
    my @timeProg = ($timeCmd);
    if ( $timeCmdOutput !~ /^\s*N\s*$/i ) {
        my $expResultsDir = experimentTempResultsDir( );
        civitasRemoteExec( $host, "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/createDir.pl", $expResultsDir );
        my $expResults = experimentTempResultsDir( "time", $kind, $host, $port );
        @timeProg = ( @timeProg, "--output=$expResults" );
    }
    @prog = ( @timeProg, @prog );
}
#print join(' ', @prog). "\n";
civitasRemoteExec( $host, @prog, "&" );
