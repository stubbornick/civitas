#!/usr/bin/perl

use strict;
use warnings;

unless ($#ARGV == 0) {
	die "Usage: copyaliases.pl <results directory>\n";
}

my $resultsDir = $ARGV[0];

my @aliases = (
	["chaff0", "anon100"],
	["auth4", "anon100"],
	["anon100", "voter100"],
	["anon20", "voter20"],
	["anon30", "voter30"],
	["anon40", "voter40"],
	["anon60", "voter60"],
	["anon70", "voter70"],
	["anon80", "voter80"],
	["anon90", "voter90"],
    ["voter100", "anon100"]);

foreach my $expPair (@aliases) {
	my $alias = $$expPair[0];
	my $real = $$expPair[1];

	my $rep = 1;
	for (my $rep = 1; 1; $rep++) {
		my $expDir = "$resultsDir/$real-$rep";
		last unless -e $expDir; # No more repetitions of experiment

		my $aliasDir = "$resultsDir/$alias-$rep";
		if ( -e $aliasDir ) {
			print("Warning: $aliasDir already exists.  Not touching it.\n");
			next;
		}

		my $cmd = "cp -r $expDir $aliasDir";
		print("$cmd\n");
		system($cmd);
	}
}

