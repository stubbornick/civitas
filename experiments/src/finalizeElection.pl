#!/usr/bin/perl
# CIVITAS
#
# This script performs the actions required by the
# supervisor to finalize an election.

use FindBin;                # where is this script installed?
use lib $FindBin::Bin;      # include this directory in the library search path
use Civitas::Experiments;
use strict;
use warnings;

sub usage {
    print <<USAGE;
usage: finalizeElection.pl experimentDescriptionFile
    Perform the actions required by the supervisor to finalize the 
    election described by the experiment description file.
USAGE
    exit;
}
if ( $#ARGV != 0 ) {
    usage();
}
initExp( $ARGV[0] );

# stop the voting
debugprint "Supervisor: finalize the election\n";
civitasExec( "$CIVITAS/bin/civitasrun", "civitas.supervisor.cli.Main", "event", "finalize", $supPublicKey_file, $supPrivateKey_file, "message",
        "auto-finalize, without even looking at the results",
        "teller", "1", "<$electionID_file" );
