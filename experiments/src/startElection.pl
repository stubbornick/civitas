#!/usr/bin/perl
# CIVITAS
#
# This script performs the actions required by the
# supervisor and registrar to start the election.

use FindBin;                # where is this script installed?
use lib $FindBin::Bin;      # include this directory in the library search path
use Civitas::Experiments;
use strict;
use warnings;

sub usage {
    print <<USAGE;
usage: startElection.pl experimentDescriptionFile
    Perform the actions required by the supervisor and registrar
    to finalize the election described by the experiment description
    file.
USAGE
    exit;
}
if ( $#ARGV != 0 ) {
    usage();
}
initExp( $ARGV[0] );

# create the bulletin board. This creates the file $electionID_file
debugprint "Supervisor: create board\n";
civitasExec( "$CIVITAS/bin/civitasrun", "civitas.supervisor.cli.Main", "create", $adminBBhost, $adminBBport, $supPublicKey_file, $supPrivateKey_file, $electionID_file );

# generate election details. This creates the file $electionDetails_file
debugprint "Generate election details\n";
civitasExec( "$CIVITAS/bin/civitasrun", "civitas.GenerateTestFiles", "electionDetails", $electionID_file, $supPublicKey_file, $regPublicKey_file,
          $elGamalParams_file, $sharedKeyLength, $VOTER_ANONYMITY,         $NONCE_LENGTH,     $electionDetails_file );

# post the election details
debugprint "Supervisor: post election details\n";
civitasExec( "$CIVITAS/bin/civitasrun", "civitas.supervisor.cli.Main", "initialize", $supPublicKey_file, $supPrivateKey_file, "<$electionDetails_file" );

# generate the teller details.
debugprint "Generate teller details\n";
my @tellerDetailsArgs = ();
for ( my $n = 1 ; $n <= $NUM_TAB_TELLERS ; $n++ ) {
    my $index  = $n - 1;
    my $pubKey = TabTellPublicKeyFile($n);
    push( @tellerDetailsArgs, ( "-tab", $TAB_TELLER_HOSTS[$index], $TAB_TELLER_PORTS[$index], $pubKey ) );
}
for ( my $n = 1 ; $n <= $NUM_REG_TELLERS ; $n++ ) {
    my $index  = $n - 1;
    my $pubKey = RegTellPublicKeyFile($n);
    push( @tellerDetailsArgs, ( "-reg", $REG_TELLER_HOSTS[$index], $REG_TELLER_PORTS[$index], $pubKey ) );
}
for ( my $n = 1 ; $n <= $NUM_VOTER_BBS ; $n++ ) {
    my $index  = $n - 1;
    my $pubKey = VoterBBPublicKeyFile($n);
    push( @tellerDetailsArgs, ( "-bb", $VOTER_BB_HOSTS[$index], $VOTER_BB_PORTS[$index], $pubKey ) );
}
civitasExec( "$CIVITAS/bin/civitasrun", "civitas.GenerateTestFiles", "tellerDetails", $tellerDetails_file, @tellerDetailsArgs );
sleep 2;

# request participation from tellers
debugprint "Supervisor: request participation from tellers\n";
civitasExec( "cat",     $electionID_file,   $tellerDetails_file, "|", "$CIVITAS/bin/civitasrun", "civitas.supervisor.cli.Main",
          "request", $supPublicKey_file, $supPrivateKey_file );

# confirm participation from tellers
debugprint "Supervisor: confirm participation from tellers\n";
civitasExec( "cat",     $electionID_file,   $tellerDetails_file, "|", "$CIVITAS/bin/civitasrun", "civitas.supervisor.cli.Main",
          "confirm", $supPublicKey_file, $supPrivateKey_file );

# start the election
debugprint "Supervisor: start the election\n";
civitasExec( "$CIVITAS/bin/civitasrun", "civitas.supervisor.cli.Main", "event", "start", $supPublicKey_file, $supPrivateKey_file, "<$electionID_file" );
sleep 2;

# ********************************
# this is code for the registrar
# ********************************
# post the electoral roll estimate
debugprint "Registrar: Generate and post electoral roll estimate for $NUM_VOTERS voters\n";
civitasExec( "cat", $electionID_file, "|", "$CIVITAS/bin/civitasrun", "civitas.registrar.cli.Main", "estimate", $regPublicKey_file, $regPrivateKey_file, $NUM_VOTERS );

# generate electoral roll
debugprint "Generate electoral roll for $NUM_VOTERS voters\n";
my @voterArgs = ();
for ( my $n = 1 ; $n <= $NUM_VOTERS ; $n++ ) {
    push( @voterArgs, VoterEGPublicKeyFile($n), VoterPublicKeyFile($n) );
}
civitasExec( "$CIVITAS/bin/civitasrun", "civitas.GenerateTestFiles", "electoralRoll", "$LOCAL_DATA_DIR/electoralRoll.xml", $electionDetails_file, @voterArgs );

# post the electoral roll
debugprint "Registrar: post the electoral roll\n";
civitasExec( "cat", $electionID_file, "$LOCAL_DATA_DIR/electoralRoll.xml",
          "|", "$CIVITAS/bin/civitasrun", "civitas.registrar.cli.Main", "roll", $regPublicKey_file, $regPrivateKey_file );
