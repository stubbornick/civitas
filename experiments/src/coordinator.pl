#!/usr/bin/perl
# CIVITAS
#
# This script coordinates one or more experiments.

use FindBin;                # where is this script installed?
use lib $FindBin::Bin;      # include this directory in the library search path
use Civitas::Experiments;
use Cwd;
use strict;
use warnings;

    print "And the civitas dir is $CIVITAS\n";

if ( $#ARGV < 0 ) {
    print <<USAGE;
usage: coordinater.pl experimentDescFile [experimentDescFile ...]
    Takes one or more experiment description files as arguments, and 
    coordinates each experiment in turn, by (re)starting tellers, and
    starting the supervisor, registrar, voter scripts, etc.
USAGE
    exit;
}
foreach my $expDesc (@ARGV) {
    debugprint("******* Processing experiment $expDesc ********\n");

    # read in the experiment description
    initExp($expDesc);

    # make sure the results directory exists
    my $rdir = experimentResultsDir();
    debugprint("Putting results in $rdir\n");
    if ( -e $rdir ) {

        # the directory exists. Move it to another location
        my $i = 1;
        while ( -e "$rdir-$i" ) {
            $i++;
        }
        debugprint("Moving existing results directory to $rdir-$i\n");
        die("Could not move $rdir. $!. Stopping") unless rename( $rdir, "$rdir-$i" );
    }
    createDirectory($rdir);

    # clean out the data dirs directories
    my @freshDirs = ( $LOCAL_DATA_DIR, $CENTRAL_DATA_DIR, experimentTempResultsDir() );
    foreach my $freshDir (@freshDirs) {
        if ( -e $freshDir ) {
            system("rm -rf $freshDir");
        }
        createDirectory($freshDir);
    }

    # put some info into the results directory
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
    my $timestamp = sprintf "%4d-%02d-%02d %02d:%02d:%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec;
    my $currDir = getcwd();
    my $INFOFILE;
    open( INFOFILE, ">$rdir/info.txt" ) or die("$!. Stopped");
    print INFOFILE <<ENDOFINFO;
Experiment started at $timestamp
Current directory $currDir
ENDOFINFO
    close(INFOFILE);

	# record the experiment parameters
	my $PARAMFILE;
	open (PARAMFILE, ">$rdir/params.txt" ) or die("$!. Stopped");
	print PARAMFILE <<EOF;
$paramLabels
$params
EOF
	close(PARAMFILE);

    # kill any tellers and boards if needed
    civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/killServers.pl", $expDesc );

    # generate test data if needed
    civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/generateKeys.pl", $expDesc, "-generate" );

    # start up the tellers and boards
    civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/startServer.pl",
              $expDesc, "bb", $adminBBhost, $adminBBport, $bbPublicKey_file, $bbPrivateKey_file, '-log' );
    for ( my $n = 1 ; $n <= $NUM_TAB_TELLERS ; $n++ ) {
        my $index = $n - 1;
        my ( $pubKey, $privKey ) = ( TabTellPublicKeyFile($n), TabTellPrivateKeyFile($n) );
        civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/startServer.pl",
                  $expDesc, "tab",
                  $TAB_TELLER_HOSTS[$index],
                  $TAB_TELLER_PORTS[$index],
                  $pubKey, $privKey );
    }
    for ( my $n = 1 ; $n <= $NUM_REG_TELLERS ; $n++ ) {
        my $index = $n - 1;
        my ( $pubKey, $privKey ) = ( RegTellPublicKeyFile($n), RegTellPrivateKeyFile($n) );
        civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/startServer.pl",
                  $expDesc, "reg",
                  $REG_TELLER_HOSTS[$index],
                  $REG_TELLER_PORTS[$index],
                  $pubKey, $privKey );
    }
    for ( my $n = 1 ; $n <= $NUM_VOTER_BBS ; $n++ ) {
        my $index = $n - 1;
        my ( $pubKey, $privKey ) = ( VoterBBPublicKeyFile($n), VoterBBPrivateKeyFile($n) );
        civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/startServer.pl",
                  $expDesc, "bb", $VOTER_BB_HOSTS[$index], $VOTER_BB_PORTS[$index], $pubKey, $privKey );
    }

    # wait until the admin bulletin board has started up.
    my $bbSleep = 3;
    while ( !system("$CIVITAS/bin/civitasrun civitas.bboard.server.GenericBBSUtil alive $adminBBhost $adminBBport") ) {
        debugprint("Waiting for admin BB... ($bbSleep secs)\n");
        sleep $bbSleep;    # wait for a bit
    }

    # perform the supervisor's election start script
    civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/startElection.pl", $expDesc );

    # perform the voters script
    civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/vote.pl", $expDesc );

    # perform the supervisor's election stop script.
    civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/stopElection.pl", $expDesc );

    # wait until the election is tabulated
    civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/waitForElection.pl", $expDesc );

    # finalize the election
    civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/finalizeElection.pl", $expDesc );

    # gather results from servers before killing them
    my $expResults = experimentResultsDir("adminBB");
    civitasExec( "$CIVITAS/bin/civitasrun", "civitas.bboard.server.GenericBBSUtil", "results", $adminBBhost, $adminBBport, ">$expResults" );
    for ( my $n = 1 ; $n <= $NUM_TAB_TELLERS ; $n++ ) {
        my $index = $n - 1;
        $expResults = experimentResultsDir("tabTeller$n");
        civitasExec( "$CIVITAS/bin/civitasrun", "civitas.TellerUtil", "results", $TAB_TELLER_HOSTS[$index], $TAB_TELLER_PORTS[$index] + 10000, ">$expResults" );
    }
    for ( my $n = 1 ; $n <= $NUM_REG_TELLERS ; $n++ ) {
        my $index = $n - 1;
        $expResults = experimentResultsDir("regTeller$n");
        civitasExec( "$CIVITAS/bin/civitasrun", "civitas.TellerUtil", "results", $REG_TELLER_HOSTS[$index], $REG_TELLER_PORTS[$index] + 10000, ">$expResults" );
    }
    for ( my $n = 1 ; $n <= $NUM_VOTER_BBS ; $n++ ) {
        my $index = $n - 1;
        $expResults = experimentResultsDir("voterBB$n");
        civitasExec( "$CIVITAS/bin/civitasrun", "civitas.bboard.server.GenericBBSUtil", "results", $VOTER_BB_HOSTS[$index], $VOTER_BB_PORTS[$index], ">$expResults" );
    }

    # kill the servers
    civitasExec( "perl", "-I$CIVITAS/experiments/src", "$CIVITAS/experiments/src/killServers.pl", $expDesc );

    # gather some more results
    
    # get disk usage for the bboards
    $expResults = experimentResultsDir("adminBB");
    my $storageResults = experimentResultsDir( "storage", "adminBB" );
    my $bbStorageDir = getStorageDir($expResults);
    if ( $bbStorageDir !~ /^N\/A$/i ) {
        civitasRemoteExec( $adminBBhost, "du -hc", $bbStorageDir, ">$storageResults" );
    }
    for ( my $n = 1 ; $n <= $NUM_VOTER_BBS ; $n++ ) {
        my $index = $n - 1;
        $expResults = experimentResultsDir("voterBB$n");
        my $storageResults = experimentResultsDir( "storage", "voterBB$n" );
        my $bbStorageDir = getStorageDir($expResults);
        if ( $bbStorageDir !~ /^N\/A$/i ) {
            civitasRemoteExec( $VOTER_BB_HOSTS[$index], "du -hc", $bbStorageDir, ">$storageResults" );
        }
    }

    # copy results from local machines over 
    my $expResultsDir     = experimentResultsDir();
    my $expTempResultsDir = experimentTempResultsDir();
    sleep 10; # wait a little, for the time commands, and logs, to finish writing their output.
    my @uniqHosts = experimentUniqueHosts();
    foreach my $host (@uniqHosts) {
        my @cmd = ( $host, "cp $expTempResultsDir/\\\* $expResultsDir" );
        civitasRemoteExec @cmd;
    }
    civitasExec ( "cp $expTempResultsDir/* $expResultsDir" ); # need to leave the wildcard unescaped, very annoying...

    # XXX TODO put the results from various files into a single, nicely formatted file
    # move the results to a nicely numbered directory
    $rdir = experimentResultsDir();
    if ( -e $rdir ) {

        # the directory exists. Move it to another location
        my $i = 1;
        while ( -e "$rdir-$i" ) {
            $i++;
        }
        debugprint("Moving results directory to $rdir-$i\n");
        warn("Could not move $rdir. $!, ") unless rename( $rdir, "$rdir-$i" );
    }
}

sub getStorageDir {
    my ($resultsFile) = @_;
    my $INPUTFILE;
    open( INPUTFILE, $resultsFile ) or die("Could not open $resultsFile $!");
    my $line;
    foreach $line (<INPUTFILE>) {
        chomp($line);
        if ( $line =~ /^\s*storageDir\s*:\s*(.*\S)\s*$/ ) {
            close(INPUTFILE);
            return $1;
        }
    }
    close(INPUTFILE);
    return "";
}
