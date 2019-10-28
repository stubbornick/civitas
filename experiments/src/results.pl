#!/usr/bin/perl

# results.pl: Collect experiment results.
# Author: Michael Clarkson

use strict;
use warnings;

##########################################
# Process options
##########################################
use Getopt::Long;

my $index = 0;
my $errorbar = 0;
my $slidescale = 0;
GetOptions( "index" => \$index,
            "errorbar" => \$errorbar,
			"slidescale" => \$slidescale);

unless ($#ARGV == 1) {
	die "Usage: results.pl [--errorbar | --index | --slidescale] <results directory> <output file>\n";
}
##########################################

# Constants
my $FILE = "file";
my $LABEL = "prefix";
my $NAME = "name";
my $BASENAME = "basename";
my $PARAM_VALS = "paramvals";
my $AXIS = "axis";
my $SCALE = "scale";

# Measurements
my %tabWallClock = ($FILE   => "adminBB", 
		    $LABEL  => "elapsedStopToResults",
		    $NAME   => "tabWallClock",
		    $AXIS   => "Wall clock (hr.)",
	        $SCALE  => "./60000 ./60" );
my %tabTellUser =  ($FILE   => "time-tab-auth",
		    $LABEL  => "User time",
		    $NAME   => "tabTellUser",
	        $AXIS   => "User time (hr.)",
	        $SCALE  => "./60 ./60" );
my %tabTellCPU =   ($FILE   => "time-tab-auth",
		    $LABEL  => "Percent of CPU",
		    $NAME   => "tabTellCPU", 
	            $AXIS   => "%CPU",
	            $SCALE  => "" );
			
my @measurements = (\%tabWallClock, \%tabTellUser, \%tabTellCPU);
			
# Experiments
my %simpleGroup = ($BASENAME => "simple",
  		   $PARAM_VALS => [1, 2, 3],
	           $AXIS => "N/A" );
my %voterGroup = ($BASENAME => "voter",
		  $PARAM_VALS => [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500,1000],
	          $AXIS => "V" );
my %authGroup  = ($BASENAME => "auth",
		  $PARAM_VALS => [1, 2, 3, 4, 5, 6, 7, 8],
	          $AXIS => "A" ); 
my %chaffGroup = ($BASENAME => "chaff",
		  $PARAM_VALS => [0, 1, 2, 5, 8, 10, 20, 30, 40, 50],
	          $AXIS => "% Chaff" );
my %anonGroup  = ($BASENAME => "anon",
		  $PARAM_VALS => [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 125, 150, 200, 300],
	          $AXIS => "K" );
my %anon160Group  = ($BASENAME => "anon160key",
		  $PARAM_VALS => [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 125, 150, 200, 300],
	          $AXIS => "K" );

#my @experimentGroups = (\%simpleGroup);
my @experimentGroups = (\%voterGroup, \%authGroup, \%chaffGroup, \%anonGroup);
#my @experimentGroups = (\%voterGroup, \%authGroup, \%anonGroup, \%anon160Group);

my $resultsDir = $ARGV[0];  
my $resultsFile = $ARGV[1];

open(RESULTS, "> $resultsFile") or 
 	die "Cannot open output file $resultsFile: $!";

print RESULTS "% Generated from $resultsDir\n";
print RESULTS "% " . localtime() . "\n\n"; 

my $script = <<"EOF";
if (str2num(version('-release')) < 14) 
  error('Requires Matlab R14'); 
end
EOF
print RESULTS $script;


print RESULTS "\n\n%------------------------------------------------------\n";
print RESULTS "% Data\n";
print RESULTS "%------------------------------------------------------\n\n\n";


foreach my $group_ref (@experimentGroups) {
	my $groupName = $group_ref->{$BASENAME};
	my $paramVal_ref = $group_ref->{$PARAM_VALS};

	print RESULTS "$groupName\_labels = [ ";
	foreach my $paramVal (@$paramVal_ref) {
		if ($groupName eq 'chaff') {
			my $c = $paramVal/100.0;
			my $adjx;
			if ($c == 0) {
			   $adjx = 0;
			} else {
			   $adjx = 100 * (2/(1 + 1/$c));
			}
			print RESULTS "$adjx ";
		} else {
			print RESULTS "$paramVal ";
		}
	}
	print RESULTS "];\n";
		
	foreach my $meas_ref (@measurements) {
		my $measFilePrefix = $meas_ref->{$FILE};
		my $label = $meas_ref->{$LABEL};
		my $measName = $meas_ref->{$NAME};

		foreach my $paramVal (@$paramVal_ref) {

			my @meas = ();
		
			my $rep = 1;
			while (1) {
				my $expDir = "$resultsDir/$groupName$paramVal-$rep";
				last unless -e $expDir; # No more repetitions of experiment

				my @measFiles = glob("$expDir/$measFilePrefix*");
				foreach my $measFile (@measFiles) {
					open(MEASFILE, "< $measFile") or
						die "Missing file $measFile: $!";
					my @lines = <MEASFILE>; # Inefficient
					close MEASFILE;

					my @match = grep {/$label/} @lines;
					unless (exists $match[0]) {
						print "Missing measurement \"$label\" in file $measFile\n";
						next;
					}
					
					# Assume: only first match from grep matters
					$match[0] =~ /$label.*:\s*([:\.\d]+)/;
					push @meas, ($1); 
				}

				$rep++;
			}

			my $values = join(" ", @meas);
			my $arrayName = "$groupName$paramVal\_$measName";
			print RESULTS "$arrayName = [$values];\n"; 
			print RESULTS "$arrayName\_mean = mean($arrayName);\n"; 
			print RESULTS "$arrayName\_std = std($arrayName);\n"; 
		}

		print RESULTS "$groupName\_$measName = [\n";
		foreach my $paramVal (@$paramVal_ref) {
			print RESULTS "\t[ $groupName$paramVal\_$measName\_mean "
		                . "  $groupName$paramVal\_$measName\_std ];\n"
		}
		print RESULTS "];\n";

		print RESULTS "$groupName\_$measName\_std_pct_mean = $groupName\_$measName(:,2) ./ $groupName\_$measName(:,1) .* 100;\n";

	
	}
}

print RESULTS "std_pct_mean = [\n";
foreach my $group_ref (@experimentGroups) {
	my $groupName = $group_ref->{$BASENAME};

	foreach my $meas_ref (@measurements) {
		my $measName = $meas_ref->{$NAME};
		print RESULTS "\tmax($groupName\_$measName\_std_pct_mean),\n";
	}

}
print RESULTS "];\n";


print RESULTS "\n\n%------------------------------------------------------\n";
print RESULTS "% Graphs\n";
print RESULTS "%------------------------------------------------------\n\n\n";

my $opts;
my $plotopts;

if ($slidescale) {
	$opts = "opts=struct('width', 12, 'height', 6, 'FontSize', 24, 'LineWidth', 1.5, 'Color', 'rgb', 'LockAxes','1','FontMode','fixed','LineMode','fixed');\n\n";
	$plotopts = "'MarkerSize',6,'MarkerFaceColor','k','MarkerEdgeColor','k'";
} else { # paper scale
	$opts = "opts=struct('width', 3.5, 'height', 1.5, 'FontSize', 8, 'LineWidth', .5, 'Color', 'rgb', 'LockAxes','1','FontMode','fixed','LineMode','fixed');\n\n";
	$plotopts = "'MarkerSize',1.5,'MarkerFaceColor','b'";
}

print RESULTS $opts;

my $subplot = 1;

foreach my $group_ref (@experimentGroups) {
	my $groupName = $group_ref->{$BASENAME};
	my $xAxisLabel = $group_ref->{$AXIS};

	foreach my $meas_ref (@measurements) {
		my $measName = $meas_ref->{$NAME};
		my $yAxisLabel = $meas_ref->{$AXIS};
		my $scale = $meas_ref->{$SCALE};

		if ($index) {
			print RESULTS "subplot(4,3,$subplot);\n";
			$subplot++;
		} else {
			print RESULTS "figure;\n";
		}

		if ($errorbar) {
			print RESULTS "errorbar($groupName\_labels,$groupName\_$measName(:,1)$scale,$groupName\_$measName(:,2)$scale,'o-',$plotopts);\n";
		} else {
			print RESULTS "plot($groupName\_labels,$groupName\_$measName(:,1)$scale,'o-',$plotopts);\n";
		}

		print RESULTS "xlabel('$xAxisLabel');\n";
		print RESULTS "ylabel('$yAxisLabel');\n";

		if ($index) {
			#
		} else {
			print RESULTS "exportfig(gcf, '$groupName-$measName.eps', opts);\n";
			print RESULTS "close\n";
		}
	}

}

if ($index) {
	print RESULTS "print -dpdf index.pdf;\n";
}

print RESULTS "\n\n%------------------------------------------------------\n";
print RESULTS "% SPECIAL CASE GRAPHS\n";
print RESULTS "%------------------------------------------------------\n\n\n";

if ($slidescale) {
	$plotopts = ",'MarkerSize',12";
} else { # paper scale
	$plotopts = "";
}

my @vs = (10, 100, 200, 300, 400, 500, 1000);

print RESULTS "vl = [ ";
foreach my $paramVal (@vs) {
	print RESULTS "$paramVal ";
}
print RESULTS "];\n";

my $voterName = $voterGroup{$BASENAME};
my $tabWallClockName = $tabWallClock{$NAME};
my $scale = $tabWallClock{$SCALE};
my $xaxis = $voterGroup{$AXIS};
my $yaxis = $tabWallClock{$AXIS};

print RESULTS "tabt = [ ";
foreach my $paramVal (@vs) {
	print RESULTS "\t$voterName$paramVal" . "_" . "$tabWallClockName" . "_" . "mean$scale\n";
}
print RESULTS "];\n";

my $yaxismax = 10;
$script = <<"EOF";
figure;

[fit,s,mu] = polyfit(vl,tabt',1);
fitval = polyval(fit,vl,s,mu);
plot(vl,fitval,':',vl,tabt,'+'$plotopts);
xlabel('$xaxis');
ylabel('$yaxis');
axis([0 1050 0 $yaxismax]);

EOF
print RESULTS $script;

unless ($index) {
	print RESULTS "exportfig(gcf,'$voterName-$tabWallClockName.eps',opts);\n";
}



close RESULTS;



