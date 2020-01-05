#!/usr/bin/perl
# CIVITAS
#
# This script executes on servers after files have been deployed on them
use strict;
use warnings;

sub usage {
    print <<USAGE;
usage: deploy.pl deployDir
    Performs any actions needed to unpack the files deployed.
USAGE
    exit;
}
if ( $#ARGV != 0 ) {
    usage();
}

# perform actions on the machine we just deployed code to
# XXX TODO
my ($deployDir) = @ARGV;
die("$deployDir does not exist on this machine!") if ( !( -e $deployDir ) );
if ( -e "$deployDir/ssh" ) {
    system("cp $deployDir/ssh/* ~/.ssh");
    chmod (0600, "~/.ssh/id_rsa");
}
else {
    warn("Did not find ssh directory as expected!");
}

# move the runtime library
system("cp $deployDir/libjifrt.so $deployDir/civitas/lib");

# move the security policy files to javahome, to allow unlimited strength crypto
system("cp $deployDir/*.jar /opt/sun-jdk-1.5.0.03/jre/lib/security");

# make sure that the appropriate directories are mounted.
if ( !( -e "/home/nfs/users/civitas" ) ) {
    system("mount /home/nfs/users");
}
# make sure that /usr/bin/java exists
if ( !( -e "/usr/bin/java" ) ) {
    system("ln -s /opt/sun-jdk-1.5.0.03/bin/java /usr/bin/java");
}

