#!/usr/bin/perl
# CIVITAS
#
# This script populates the $CIVITAS/experiments/deploy directory

sub usage {
    print <<USAGE;
usage: makeDeploy.pl
    Should only be executed from the $CIVITAS directory. Populates
    $CIVITAS/experiments/deploy
USAGE
    exit;
}
if ( $#ARGV >= 0 ) {
    usage();
}

if (-e "experiments/deploy/civitas") {
    system("rm -rf experiments/deploy/civitas" );
}
mkdir("experiments/deploy/civitas") or die($!);
mkdir("experiments/deploy/civitas/lib") or die($!);
mkdir("experiments/deploy/civitas/experiments") or die($!);
mkdir("experiments/deploy/civitas/bin") or die($!);
mkdir("experiments/deploy/civitas/testDataEGParams") or die($!);

system("cp -r classes experiments/deploy/civitas" );
system("cp -r lib/*.jar experiments/deploy/civitas/lib" );
system("cp -r lib/*.zip experiments/deploy/civitas/lib" );
system("cp -r experiments/src experiments/deploy/civitas/experiments" );
system("cp -r experiments/*.* experiments/deploy/civitas/experiments" );
system("cp -r testDataEGParams/*.xml experiments/deploy/civitas/testDataEGParams" );
system("cp -r bin/civitasrun experiments/deploy/civitas/bin" );

# delete the CVS directories
system('find experiments/deploy/civitas -depth -name CVS -prune -exec rm -rf {} \;' );
