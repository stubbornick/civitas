#!/usr/bin/perl
# CIVITAS
#
# This script kills CIVITAS servers on the current machine.

use FindBin;                # where is this script installed?
use lib $FindBin::Bin;      # include this directory in the library search path
use Civitas::Experiments;
use strict;

sub usage {
    print <<USAGE;
usage: killServers.pl [experimentDescriptionFile]
    If no experiment description file is given, try to kill all CIVITAS
    servers on this machine. Otherwise, try to kill all CIVITAS servers
    on machines listed in the experiment description file.
USAGE
    exit;
}
if ( $#ARGV == 0 ) {
    initExp( $ARGV[0] );

    # go to each unique host listed, and kill the servers on that host
    my @uniqHosts = experimentUniqueHosts();
    foreach my $host (@uniqHosts) {
        my @cmd = ( $host, "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/killServers.pl" );
        civitasRemoteExec @cmd;
    }
    exit;
}
elsif ( $#ARGV > 0 ) {
    usage();
}
my @pids = findPIDStoKill();
foreach my $pid (@pids) {
    debugprint "killing CIVITAS server with pid $pid\n";
    # kill( 'TERM', $pid );
    system("kill -9 $pid");
}

sub findPIDStoKill {
    if ( $ENV{'OS'} =~ /windows/i ) {
        return findPIDStoKillWindows();
    }
    else {
        open( PS, $psCmd ." |" );
        my @possibles = ();
        foreach my $line (<PS>) {
            chop($line);
            $line =~ s/^\s+//;
            #  make sure we don't kill the time command!
            push( @possibles, $line ) if ( $line =~ /java.*civitas\S+server/  && $line !~ /time.*civitasrun/);
        }
        close PS;
        foreach my $entry (@possibles) {
            my @proc = split /\s+/, $entry, -1;
            push( @pids, $proc[$psCmdPidCol] );
        }
        return @pids;
    }
}

sub findPIDStoKillWindows {

    # this is a big hack. There is no nice way to figure out which
    # java processes are running civitas servers.
    open( PS, "$psCmd |" );
    my @possibles = ();
    foreach my $line (<PS>) {
        chop($line);
        push( @possibles, $line ) if ( $line =~ /bin\/java/ );
    }
    close PS;
    foreach my $entry (@possibles) {
        my @proc = split /\s+/, $entry, -1;
        push( @pids, $proc[2] );
    }
    return @pids;
}
