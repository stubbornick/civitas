#!/usr/bin/perl
# CIVITAS
#
# This script deploys files to servers used in the experiments

use FindBin;                # where is this script installed?
use lib $FindBin::Bin;      # include this directory in the library search path
use Civitas::Experiments;
use strict;
use warnings;

sub usage {
    print <<USAGE;
usage: deploy.pl sourceDir targetDir serversFile experimentDescriptionFile
    Copies everything from sourceDir to targetDir on all servers listed
    in the serversFile, using the credentials supplied in the
    experimentDescriptionFile.

    It also executes "postdeploy.pl targetDir" on each server that it copied the
    source directory to.
USAGE
    exit;
}
if ( $#ARGV != 3 ) {
    usage();
}
my ( $sourceDir, $targetDir, $serversFile, $expDescFile ) = @ARGV;
initExp($expDescFile);
my $INPUTFILE;
open( INPUTFILE, $serversFile ) or die("Could not open $serversFile");

# find the post deploy script
my $deployScript;
if ( -e "$sourceDir/postdeploy.pl" ) {
    $deployScript = "$targetDir/postdeploy.pl";
}
elsif ( -e "$sourceDir/experiments/src/postdeploy.pl" ) {
    $deployScript = "$targetDir/experiments/src/postdeploy.pl";
}
elsif ( -e "$sourceDir/civitas/experiments/src/postdeploy.pl" ) {
    $deployScript = "$targetDir/civitas/experiments/src/postdeploy.pl";
}

# process each server
debugprint ("Processing $serversFile\n");
foreach my $server (<INPUTFILE>) {
    $server =~ s/\s+//g;
    if ( $server =~ /^\s*#/ || $server =~ /^\s*$/ ) {
        next;
    }

    # we need to deploy to $server
    debugprint("Cleaning $server:$targetDir\n");
    civitasRemoteExec( $server, "rm -rf $targetDir" );
    debugprint ("Copying $sourceDir to $server:$targetDir\n");
    civitasRemoteCopy( $server, $sourceDir, $targetDir );

    # now execute postdeploy on that server
    if ( defined $deployScript ) {
        debugprint "Executing $deployScript on $server\n";
        civitasRemoteExec( $server, "perl", $deployScript, $targetDir );
    }
}
close(INPUTFILE);