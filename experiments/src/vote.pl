#!/usr/bin/perl
# CIVITAS
#
# This script performs the actions required by the
# voters of an election.

use FindBin;                # where is this script installed?
use lib $FindBin::Bin;      # include this directory in the library search path
use Civitas::Experiments;
use strict;
use warnings;

sub usage {
    print <<USAGE;
usage: vote.pl experimentDescriptionFile
    Perform the voter actions for the election described by the
    experiment description file.
USAGE
    exit;
}
if ( $#ARGV != 0 ) {
    usage();
}
initExp( $ARGV[0] );

# Vote, dividing the votes equally between the voter hosts.
my ( $votesRemaining, $hostsRemaining, $dupVotesRemaining, $invVotesRemaing ) = ( $NUM_VOTERS, $NUM_VOTER_HOSTS, $NUM_DUPLICATE_BALLOTS, $NUM_INVALID_BALLOTS );
my $voteIndex = 1;
for ( my $i = 1 ; $i <= $NUM_VOTER_HOSTS ; $i++ ) {
    my ( $votesForThisHost, $dupVotesForThisHost, $invVotesForThisHost ) =
      computeParamsForHost( $votesRemaining, $hostsRemaining, $dupVotesRemaining, $invVotesRemaing );
    if ( $votesForThisHost > $votesRemaining ) {
        $votesForThisHost = $votesRemaining;
    }
    if ( $dupVotesForThisHost > $dupVotesRemaining ) {
        $dupVotesForThisHost = $dupVotesRemaining;
    }
    if ( $invVotesForThisHost > $invVotesRemaing ) {
        $invVotesForThisHost = $invVotesRemaing;
    }
    $votesRemaining    = $votesRemaining - $votesForThisHost;
    $dupVotesRemaining = $dupVotesRemaining - $dupVotesForThisHost;
    $invVotesRemaing   = $invVotesRemaing - $invVotesForThisHost;
    $hostsRemaining    = $hostsRemaining - 1;
    my $voterHostFinishedFile = "$CENTRAL_DATA_DIR/voterHost$i.txt";
    if ( -e $voterHostFinishedFile ) {
        system("rm $voterHostFinishedFile");
    }
    if ( -e $voterHostFinishedFile ) {
        die("Couldn't delete marker file");
    }
    my @voteCmd = (
                    "$CIVITAS/bin/civitasrun",        "civitas.AutomatedVotingClient",
                    $electionDetails_file,      $tellerDetails_file,
                    "VXX",                      "'Voter VXX'",
                    VoterEGPrivateKeyFile("VXX"), VoterEGPublicKeyFile("VXX"),
                    VoterPrivateKeyFile("VXX"), VoterPublicKeyFile("VXX"),
                    $voteIndex,                 $votesForThisHost,
                    $dupVotesForThisHost,       $invVotesForThisHost,
                    $voterClientCachingFlag,
                    $voterHostFinishedFile, FileCacheRoot( "voterHost", $voteIndex ),
                    experimentTempResultsDir("voterHost", $voteIndex)
    );

    # if it's not the last one, then run it in the background
    if ( $i != $NUM_VOTER_HOSTS ) {
        push( @voteCmd, "&" );
    }
    my $host = $VOTER_HOSTS[ $i - 1 ];
    debugprint("Starting voting on $host: $votesForThisHost votes, $dupVotesForThisHost duplicates, $invVotesForThisHost invalid\n");
    civitasRemoteExec( $host, @voteCmd );
    $voteIndex = $voteIndex + $votesForThisHost;
}

# check that all the voter hosts finished
for ( my $i = 1 ; $i <= $NUM_VOTER_HOSTS ; $i++ ) {
    my $voterHostFinishedFile = "$CENTRAL_DATA_DIR/voterHost$i.txt";
    my $host                  = $VOTER_HOSTS[ $i - 1 ];
    while ( !( -e $voterHostFinishedFile ) ) {
        debugprint("Waiting for voting host $i ($host) to finish...\n");
        sleep 10;
    }
}

sub computeParamsForHost {
    my ( $numVotersRem, $numHostsRem, $numDupRem, $numInvRem ) = @_;
    my ( $x, $y, $z ) = ( $numVotersRem / $numHostsRem, $numDupRem / $numHostsRem, $numInvRem / $numHostsRem );
    $x = int($x) + ( $x > int($x) );    # take the ceiling
    $y = int($y) + ( $y > int($y) );    # take the ceiling
    $z = int($z) + ( $z > int($z) );    # take the ceiling
    return ( $x, $y, $z );
}
