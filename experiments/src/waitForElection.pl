#!/usr/bin/perl
# CIVITAS
#
# This script waits until the specified election
# is abandoned or tabulated.

use FindBin;                # where is this script installed?
use lib $FindBin::Bin;      # include this directory in the library search path
use Civitas::Experiments;
use strict;
use warnings;

sub usage {
    print <<USAGE;
usage: waitForElection.pl experimentDescriptionFile
    Waits until the election described by the experiment description
    file is either abandoned or tabulated.
USAGE
    exit;
}
if ( $#ARGV != 0 ) {
    usage();
}
initExp( $ARGV[0] );

# rather than calculate the status, which is quite expensive, we will just wait until
# either an "abandonElection" message or an "electionResults" message is posted,
# and then compute the status
my $electionDone = 0;
my @doneMetas = ("electionAbandonment", "electionResults:Teller1");
do {

    # wait for a bit
    # XXX FOR BETTER TIMING, SHOULD WE USE SOME KIND OF WAKE UP MECHANISM?
    sleep 10;

    foreach my $meta (@doneMetas) {
        my $output = `$CIVITAS/bin/civitasrun civitas.supervisor.cli.Main list meta $meta <$electionID_file`;
        if ($output =~ /<post>/) {
            # the election may be done. Go into a loop where we check the status
            do {
                $output = `$CIVITAS/bin/civitasrun civitas.supervisor.cli.Main status  <$electionID_file`;
                if ($output !~ /stopped/i) {
                    $electionDone = 1;
                }
                else {
                    sleep 10;
                }
            } while ( !$electionDone );
        }
    }

} while ( !$electionDone );
