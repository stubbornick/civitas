#!/usr/bin/perl
#
# This script processes logs produced by running Java with the
# -Xloggc:filename. It takes one or more log files,
# and produces a file that summarizes the log.
use strict;
use warnings;

sub usage {
    print <<USAGE;
usage: processGCLog.pl gclog1 [gclog2 gclog3 ...]
    Produces summaries of GC logs from the JVM. Produces files
    gclog1_summary gclog2_summary gclog3_summary ...
USAGE
    exit;
}
if ( $#ARGV < 0 ) {
    usage();
}
foreach my $gclog (@ARGV) {
    open INPUT, "< $gclog"
      or die "Can't open log file $gclog: $!";
    my ( $maxBeforeHeap, $maxTotalHeap ) = ( 0, 0 );
    foreach my $line (<INPUT>) {
        $line =~ s/\s+$//;    # remove trailing white space.
        $line =~ s/^\s+//;    # remove leading white space.

        # some sample lines:
        # 167.522: [GC 1887K->1444K(3812K), 0.0004930 secs]
        # 167.634: [Full GC 1739K->1032K(3812K), 0.0287840 secs]
        if ( $line =~ /^([\d\.]+)\s*:\s+\[(.*),\s*(.*)\]$/ ) {
            my ( $timestamp, $op, $duration ) = ( $1, $2, $3 );
            if ( $op =~ /\s(\d+)K->(\d+)K\((\d+)K\)$/ ) {
                my ( $heapbefore, $heapafter, $totalheap ) = ( $1, $2, $3 );
                $maxBeforeHeap = $heapbefore if ( $maxBeforeHeap < $heapbefore );
                $maxTotalHeap  = $totalheap  if ( $maxTotalHeap < $totalheap );
            }
            else {
                print "Warning: unknown operation '$op'\n";
            }
        }
        else {
            print "Warning: unknown line kind '$line'\n";
        }
    }
    close(INPUT);
    my $outputFile = $gclog . "_summary";
    open( OUTPUT, "> $outputFile" )
      or die "Can't open output file $outputFile: $!";
    print OUTPUT "measurements are in kB\n";
    print OUTPUT "max_heap_before_gc : $maxBeforeHeap\n";
    print OUTPUT "max_total_heap : $maxTotalHeap\n";
    close OUTPUT;
}
