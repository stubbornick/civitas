#!/usr/bin/perl
# CIVITAS
#
# This script performs the actions required by the
# supervisor to stop an election.

use FindBin;                # where is this script installed?
use lib $FindBin::Bin;      # include this directory in the library search path
use Civitas::Experiments;

sub usage {
    print <<USAGE;
usage: stopElection.pl experimentDescriptionFile
    Perform the actions required by the supervisor to stop the election
    and start the tabulation process.
USAGE
    exit;
}
if ( $#ARGV != 0 ) {
    usage();
}
initExp( $ARGV[0] );

# stop the voting
debugprint "Supervisor: stop the voting\n";
civitasExec( "$CIVITAS/bin/civitasrun", "civitas.supervisor.cli.Main", "event", "stop", $supPublicKey_file, $supPrivateKey_file, "<$electionID_file" );

# start the tabulation
debugprint "Supervisor: start the tabulation\n";
civitasExec( "$CIVITAS/bin/civitasrun", "civitas.supervisor.cli.Main", "tabulate", $supPublicKey_file, $supPrivateKey_file, "<$electionID_file" );
