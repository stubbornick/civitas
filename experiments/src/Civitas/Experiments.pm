package Civitas::Experiments;
# NOTE: this library should only be used by 
# scripts in the $CIVITAS/experiments/src directory. This is assumed
# in determining the Civitas home directory

use FindBin;
use strict;
use warnings;

# Export the package interface
BEGIN {
    use Exporter ();
    our ( $VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS );
    $VERSION = 1.02;
    @ISA     = qw(Exporter);
    @EXPORT  = qw(&initExp &civitasRemoteExec &civitasExec &civitasRemoteCopy &createDirectory &experimentUniqueHosts
      &debugprint &BBFileRoot &TabFileRoot &FileCacheRoot &experimentResultsDir &experimentTempResultsDir
      $CIVITAS $CENTRAL_DATA_DIR $LOCAL_DATA_DIR $CENTRAL_KEYS_DIR $LOCAL_KEYS_DIR
      $timeCmd $timeCmdOutput $psCmd $psCmdPidCol
      $electionID_file $electionDetails_file $tellerDetails_file
      $elGamalParams_file
      $elGamalKeyLength
      $elGamalGroupLength
      $elGamalVoterKeyParams_file
      $elGamalVoterKeyLength
      $elGamalVoterGroupLength
      $publicKeyLength
      $sharedKeyLength
      $recordMemoryUsageFlag
      $voterClientCachingFlag
      $NUM_VOTER_HOSTS @VOTER_HOSTS
      $NUM_TAB_TELLERS @TAB_TELLER_HOSTS @TAB_TELLER_PORTS &TabTellPublicKeyFile &TabTellPrivateKeyFile
      $NUM_REG_TELLERS @REG_TELLER_HOSTS @REG_TELLER_PORTS &RegTellPublicKeyFile &RegTellPrivateKeyFile
      $NUM_VOTER_BBS @VOTER_BB_HOSTS @VOTER_BB_PORTS  &VoterBBPublicKeyFile &VoterBBPrivateKeyFile
      $NUM_VOTERS $VOTER_ANONYMITY $NONCE_LENGTH $NUM_DUPLICATE_BALLOTS $NUM_INVALID_BALLOTS
      &VoterEGPublicKeyFile &VoterEGPrivateKeyFile
      &VoterPublicKeyFile &VoterPrivateKeyFile
      $adminBBhost $adminBBport $bbPublicKey_file $bbPrivateKey_file
      $regPublicKey_file $regPrivateKey_file
      $supPublicKey_file $supPrivateKey_file
	  $paramLabels $params
    );
}

# Package imports
# Declare exported variables
# Platform specific
#### Linux
our $timeCmd       = "/usr/bin/time -v";
our $timeCmdOutput = "Y";
our $psCmd         = "ps -ef -w -w";
our $psCmdPidCol   = 1;
my $os = "unknown";
$os = $^O; # Get the name of the os.
if ( $os =~ /windows/i || $os =~ /cygwin/i) {    # windows machine
    $timeCmd       = "";
    $timeCmdOutput = "N";
    $psCmd         = "ps -ef";
    $psCmdPidCol   = 1;
}
elsif ( $os =~ /darwin/i ) {    # OS X
    $timeCmd       = "/usr/bin/time -l";
    $timeCmdOutput = "N";
    $psCmd         = "ps -w -w";
    $psCmdPidCol   = 0;
}

# supplied variables from experiment file
our $CIVITAS = findCivitasDir();
our $LOCAL_DATA_DIR;
our $CENTRAL_DATA_DIR;
our $CENTRAL_KEYS_DIR;
our $LOCAL_KEYS_DIR;
our $elGamalKeyLength;
our $elGamalGroupLength;
our $elGamalVoterKeyLength;
our $elGamalVoterGroupLength;
our $publicKeyLength;
our $sharedKeyLength;
our $NUM_VOTERS;
our $VOTER_ANONYMITY;
our $NONCE_LENGTH;
our $NUM_DUPLICATE_BALLOTS;
our $NUM_INVALID_BALLOTS;
our $paramLabels = "No param labels supplied";
our $params = "No params supplied";
our $recordMemoryUsageFlag = 0;
our $voterClientCachingFlag = 1;

# computed from experiment file
our $NUM_VOTER_HOSTS  = 0;
our @VOTER_HOSTS      = ();
our $NUM_TAB_TELLERS  = 0;
our @TAB_TELLER_HOSTS = ();
our @TAB_TELLER_PORTS = ();
our $NUM_REG_TELLERS  = 0;
our @REG_TELLER_HOSTS = ();
our @REG_TELLER_PORTS = ();
our $NUM_VOTER_BBS    = 0;
our @VOTER_BB_HOSTS   = ();
our @VOTER_BB_PORTS   = ();
our $adminBBhost;
our $adminBBport;

# standard filenames
our $electionID_file;
our $electionDetails_file;
our $tellerDetails_file;
our $elGamalParams_file;
our $elGamalVoterKeyParams_file;
our $bbPublicKey_file;
our $bbPrivateKey_file;
our $regPublicKey_file;
our $regPrivateKey_file;
our $supPublicKey_file;
our $supPrivateKey_file;

# Non-exported variables
my $expFile;
my $results_dir;
my $sshUser;
my $sshIdentityFile;
my $KEY_CIVITAS_DIR           = "civitasDir";
my $KEY_LOCAL_DATA_DIR        = "localDataDir";
my $KEY_CENTRAL_DATA_DIR      = "centralDataDir";
my $KEY_LOCAL_KEYS_DIR        = "localKeysDir";
my $KEY_CENTRAL_KEYS_DIR      = "centralKeysDir";
my $KEY_RESULTS_DIR           = "resultsDir";
my $KEY_EG_PARAMS_KEY_LENGTH  = "elGamalKeyLength";
my $KEY_EG_PARAMS_GROUP_LENGTH          = "elGamalGroupLength";
my $KEY_VOTER_EG_PARAMS_KEY_LENGTH      = "elGamalVoterKeyLength";
my $KEY_VOTER_EG_PARAMS_GROUP_LENGTH    = "elGamalVoterGroupLength";
my $KEY_PUBLIC_KEY_LENGTH     = "publicKeyLength";
my $KEY_SHARED_KEY_LENGTH     = "sharedKeyLength";
my $KEY_NUM_VOTERS            = "numVoters";
my $KEY_VOTER_ANONYMITY       = "voterAnon";
my $KEY_NONCE_LENGTH          = "nonceLength";
my $KEY_NUM_DUPLICATE_BALLOTS = "numDuplicateBallots";
my $KEY_NUM_INVALID_BALLOTS   = "numInvalidBallots";
my $KEY_VOTER_HOST            = "voterHost";
my $KEY_TAB_TELLER            = "tabTeller";
my $KEY_REG_TELLER            = "regTeller";
my $KEY_VOTER_BB              = "voterBB";
my $KEY_ADMIN_BB              = "adminBB";
my $KEY_SSH_USER              = "sshUser";
my $KEY_SSH_ID_FILE           = "sshIdentityFile";
my $KEY_PARAM_LABELS          = "paramLabels";
my $KEY_PARAMS                = "params";
my $KEY_MEM_USAGE             = "recordMemUsage";
my $KEY_VOTER_CLIENT_CACHING  = "voterClientCaching";

# 1 for a real key, 2 for a real key that we should append entries
my %KNOWN_KEYS = (
                   $KEY_CIVITAS_DIR              => 1,
                   $KEY_LOCAL_DATA_DIR        => 1,
                   $KEY_CENTRAL_DATA_DIR      => 1,
                   $KEY_LOCAL_KEYS_DIR        => 1,
                   $KEY_CENTRAL_KEYS_DIR      => 1,
                   $KEY_RESULTS_DIR           => 1,
                   $KEY_EG_PARAMS_KEY_LENGTH  => 1,
                   $KEY_EG_PARAMS_GROUP_LENGTH  => 1,
                   $KEY_VOTER_EG_PARAMS_KEY_LENGTH      => 1,
                   $KEY_VOTER_EG_PARAMS_GROUP_LENGTH      => 1,
                   $KEY_PUBLIC_KEY_LENGTH     => 1,
                   $KEY_SHARED_KEY_LENGTH     => 1,
                   $KEY_NUM_VOTERS            => 1,
                   $KEY_VOTER_ANONYMITY       => 1,
                   $KEY_NONCE_LENGTH       => 1,
                   $KEY_NUM_DUPLICATE_BALLOTS => 1,
                   $KEY_NUM_INVALID_BALLOTS   => 1,
                   $KEY_VOTER_HOST            => 2,
                   $KEY_TAB_TELLER            => 2,
                   $KEY_REG_TELLER            => 2,
                   $KEY_VOTER_BB              => 2,
                   $KEY_ADMIN_BB              => 1,
                   $KEY_SSH_USER              => 1,
                   $KEY_SSH_ID_FILE           => 1,
				   $KEY_PARAM_LABELS          => 1,
				   $KEY_PARAMS                => 1,
				   $KEY_MEM_USAGE             => 1,
				   $KEY_VOTER_CLIENT_CACHING  => 1,
);

# reset the vars to initial values.
sub resetVars {
    $CIVITAS                  = findCivitasDir();
    $LOCAL_DATA_DIR        = ".";
    $CENTRAL_DATA_DIR      = ".";
    $CENTRAL_KEYS_DIR      = "$CIVITAS/experiments/keys";
    $LOCAL_KEYS_DIR        = "$CENTRAL_KEYS_DIR";
    $elGamalKeyLength      = 160;
    $elGamalGroupLength      = $elGamalKeyLength + 1;
    $elGamalVoterKeyLength = 160;
    $elGamalVoterGroupLength = $elGamalVoterKeyLength + 1;
    $publicKeyLength       = 160;
    $sharedKeyLength       = 256;
    $NUM_VOTERS            = 10;
    $VOTER_ANONYMITY       = 5;
    $NONCE_LENGTH       = 1024;
    $NUM_DUPLICATE_BALLOTS = 0;
    $NUM_INVALID_BALLOTS   = 0;
    $NUM_VOTER_HOSTS       = 0;
    @VOTER_HOSTS           = ();
    $NUM_TAB_TELLERS       = 0;
    @TAB_TELLER_HOSTS      = ();
    @TAB_TELLER_PORTS      = ();
    $NUM_REG_TELLERS       = 0;
    @REG_TELLER_HOSTS      = ();
    @REG_TELLER_PORTS      = ();
    $NUM_VOTER_BBS         = 0;
    @VOTER_BB_HOSTS        = ();
    @VOTER_BB_PORTS        = ();
    $electionID_file            = "electionID.xml";
    $electionDetails_file       = "electionDetails.xml";
    $tellerDetails_file         = "tellerDetails.xml";
    $results_dir     = "experimentResults";
    $sshUser         = "";
    $sshIdentityFile = "";
    $recordMemoryUsageFlag = 0;
    resetKeyFilenameVars();
}

# reset the vars related to key and parameter fie names to initial values. These initial
# values depend on the key lengths.
sub resetKeyFilenameVars {
    $elGamalParams_file         = "elGamalKeyParams-$elGamalKeyLength-$elGamalGroupLength.xml";
    $elGamalVoterKeyParams_file = "elGamalVoterKeyParams-$elGamalKeyLength-$elGamalGroupLength.xml";
    $bbPublicKey_file           = "bbPublicKey-$publicKeyLength.xml";
    $bbPrivateKey_file          = "bbPrivateKey-$publicKeyLength.xml";
    $regPublicKey_file          = "regPublicKey-$publicKeyLength.xml";
    $regPrivateKey_file         = "regPrivateKey-$publicKeyLength.xml";
    $supPublicKey_file          = "supPublicKey-$publicKeyLength.xml";
    $supPrivateKey_file         = "supPrivateKey-$publicKeyLength.xml";
}

sub initExp {
    resetVars();
    ($expFile) = @_;

    # read in the experiment description file
    my %properties = ();
    my $INPUTFILE;
    open( INPUTFILE, $expFile ) or die("Could not open $expFile");
    my $line;
    my $failed = 0;
    foreach $line (<INPUTFILE>) {
        chomp($line);
        if ( $line =~ /^\s*#/ || $line =~ /^\s*$/ ) {
            next;
        }
        if ( $line =~ /^(.*)=(.*)$/ ) {
            my ( $key, $value ) = ( $1, $2 );

            # strip off white space
            $key   =~ s/^\s*//;
            $key   =~ s/\s*$//;
            $value =~ s/\s*$//;
            $value =~ s/^\s*//;
            if ( defined $KNOWN_KEYS{$key} ) {
                if ( $KNOWN_KEYS{$key} == 0 ) {

                    # a bad key, but one we've already seen
                }
                elsif ( $KNOWN_KEYS{$key} == 1 ) {
                    if (defined $properties{$key}) {
	                    debugprint("WARNING $expFile: duplicate key '$key'\n");
	                }
                    $properties{$key} = $value;
                }
                elsif ( $KNOWN_KEYS{$key} == 2 ) {
                    my $oldVal = "";
                    if ( defined $properties{$key} ) {
                        $oldVal = $properties{$key} . " ";
                    }
                    $properties{$key} = $oldVal . $value;
                }
            }
            else {
                debugprint("WARNING $expFile: unexpected key '$key'\n");
                $KNOWN_KEYS{$key} = 0;
            }
        }
        else {
            debugprint("WARNING $expFile: don't know what to do with '$line'\n");
        }
    }

    # initialize the variables and data structures
	
	if ( defined $properties{$KEY_PARAM_LABELS} ) {
		$paramLabels = $properties{$KEY_PARAM_LABELS};
	}
	if ( defined $properties{$KEY_PARAMS} ) {
		$params = $properties{$KEY_PARAMS};
	}
    if ( defined $properties{$KEY_MEM_USAGE} ) {
        $recordMemoryUsageFlag = $properties{$KEY_MEM_USAGE};
    }
    if ( defined $properties{$KEY_VOTER_CLIENT_CACHING} ) {
        $voterClientCachingFlag = $properties{$KEY_VOTER_CLIENT_CACHING};
    }
    if ( defined $properties{$KEY_SSH_USER} ) {
        $sshUser = $properties{$KEY_SSH_USER};
    }
    if ( defined $properties{$KEY_SSH_ID_FILE} ) {
        $sshIdentityFile = $properties{$KEY_SSH_ID_FILE};
    }
    if ( defined $properties{$KEY_CIVITAS_DIR} ) {
        $CIVITAS = $properties{$KEY_CIVITAS_DIR};
    }
    if ( defined $properties{$KEY_LOCAL_KEYS_DIR} ) {
        $LOCAL_KEYS_DIR = $properties{$KEY_LOCAL_KEYS_DIR};
        $LOCAL_KEYS_DIR =~ s/\$CIVITAS/$CIVITAS/;
    }
    if ( defined $properties{$KEY_CENTRAL_KEYS_DIR} ) {
        $CENTRAL_KEYS_DIR = $properties{$KEY_CENTRAL_KEYS_DIR};
        $CENTRAL_KEYS_DIR =~ s/\$CIVITAS/$CIVITAS/;
    }
    if ( defined $properties{$KEY_LOCAL_DATA_DIR} ) {
        $LOCAL_DATA_DIR = $properties{$KEY_LOCAL_DATA_DIR};
        $LOCAL_DATA_DIR =~ s/\$CIVITAS/$CIVITAS/;
    }
    if ( defined $properties{$KEY_CENTRAL_DATA_DIR} ) {
        $CENTRAL_DATA_DIR = $properties{$KEY_CENTRAL_DATA_DIR};
        $CENTRAL_DATA_DIR =~ s/\$CIVITAS/$CIVITAS/;
    }
    if ( defined $properties{$KEY_RESULTS_DIR} ) {
        $results_dir = $properties{$KEY_RESULTS_DIR};
        $results_dir =~ s/\$CIVITAS/$CIVITAS/;
    }
    if ( defined $properties{$KEY_EG_PARAMS_KEY_LENGTH} ) {
        $elGamalKeyLength = $properties{$KEY_EG_PARAMS_KEY_LENGTH};
    }
    else {
		reportMissingParam($KEY_EG_PARAMS_KEY_LENGTH);
		$failed = 1;
    }
    if ( defined $properties{$KEY_EG_PARAMS_GROUP_LENGTH} ) {
        $elGamalGroupLength = $properties{$KEY_EG_PARAMS_GROUP_LENGTH};
    }
    else {
		reportMissingParam($KEY_EG_PARAMS_GROUP_LENGTH);
		$failed = 1;
    }
    if ( defined $properties{$KEY_VOTER_EG_PARAMS_KEY_LENGTH} ) {
        $elGamalVoterKeyLength = $properties{$KEY_VOTER_EG_PARAMS_KEY_LENGTH};
    }
    else {
		reportMissingParam($KEY_VOTER_EG_PARAMS_KEY_LENGTH);
		$failed = 1;
    }
    if ( defined $properties{$KEY_VOTER_EG_PARAMS_GROUP_LENGTH} ) {
        $elGamalVoterGroupLength = $properties{$KEY_VOTER_EG_PARAMS_GROUP_LENGTH};
    }
    else {
		reportMissingParam($KEY_VOTER_EG_PARAMS_GROUP_LENGTH);
		$failed = 1;
    }
    if ( defined $properties{$KEY_PUBLIC_KEY_LENGTH} ) {
        $publicKeyLength = $properties{$KEY_PUBLIC_KEY_LENGTH};
    }
    else {
		reportMissingParam($KEY_PUBLIC_KEY_LENGTH);
		$failed = 1;
		
    }
    if ( defined $properties{$KEY_SHARED_KEY_LENGTH} ) {
        $sharedKeyLength = $properties{$KEY_SHARED_KEY_LENGTH};
    }
    else {
		reportMissingParam($KEY_SHARED_KEY_LENGTH);
		$failed = 1;
    }
    
    if ( defined $properties{$KEY_NUM_VOTERS} ) {
        $NUM_VOTERS = $properties{$KEY_NUM_VOTERS};
    }
    else {
		reportMissingOptParam($KEY_NUM_VOTERS, $NUM_VOTERS);
    }
    
    if ( defined $properties{$KEY_VOTER_ANONYMITY} ) {
        $VOTER_ANONYMITY = $properties{$KEY_VOTER_ANONYMITY};
    }
    else {
   		reportMissingOptParam($KEY_VOTER_ANONYMITY, $VOTER_ANONYMITY);
    }
    if ( defined $properties{$KEY_NONCE_LENGTH} ) {
        $NONCE_LENGTH = $properties{$KEY_NONCE_LENGTH};
    }
    else {
		reportMissingParam($KEY_NONCE_LENGTH);
		$failed = 1;
		
    }
    if ( defined $properties{$KEY_NUM_DUPLICATE_BALLOTS} ) {
        $NUM_DUPLICATE_BALLOTS = $properties{$KEY_NUM_DUPLICATE_BALLOTS};
    }
    else {
		reportMissingOptParam($KEY_NUM_DUPLICATE_BALLOTS, $NUM_DUPLICATE_BALLOTS);
    }
    if ( defined $properties{$KEY_NUM_INVALID_BALLOTS} ) {
        $NUM_INVALID_BALLOTS = $properties{$KEY_NUM_INVALID_BALLOTS};
    }
    else {
		reportMissingOptParam($KEY_NUM_INVALID_BALLOTS, $NUM_INVALID_BALLOTS);
    }
    if ( defined $properties{$KEY_ADMIN_BB} ) {
        my $tellers = $properties{$KEY_ADMIN_BB};
        while ( length $tellers > 0 ) {
            $tellers =~ s/^\s*(\S+)\s+(\S+)\s*//;
            ( $adminBBhost, $adminBBport ) = ( $1, $2 );
        }
    }
    else {
		reportMissingParam($KEY_ADMIN_BB);
        $failed = 1;
    }
    if ( defined $properties{$KEY_VOTER_HOST} ) {
        my $tellers = $properties{$KEY_VOTER_HOST};
        while ( length $tellers > 0 ) {
            $tellers =~ s/^\s*(\S+)\s*//;
            $NUM_VOTER_HOSTS = push( @VOTER_HOSTS, $1 );
        }
    }
    if ( defined $properties{$KEY_TAB_TELLER} ) {
        my $tellers = $properties{$KEY_TAB_TELLER};
        while ( length $tellers > 0 ) {
            $tellers =~ s/^\s*(\S+)\s+(\S+)\s*//;
            my ( $host, $port ) = ( $1, $2 );
            $NUM_TAB_TELLERS = push( @TAB_TELLER_HOSTS, $host );
            push( @TAB_TELLER_PORTS, $port );
        }
    }
    if ( defined $properties{$KEY_REG_TELLER} ) {
        my $tellers = $properties{$KEY_REG_TELLER};
        while ( length $tellers > 0 ) {
            $tellers =~ s/^\s*(\S+)\s+(\S+)\s*//;
            my ( $host, $port ) = ( $1, $2 );
            $NUM_REG_TELLERS = push( @REG_TELLER_HOSTS, $host );
            push( @REG_TELLER_PORTS, $port );
        }
    }
    if ( defined $properties{$KEY_VOTER_BB} ) {
        my $tellers = $properties{$KEY_VOTER_BB};
        while ( length $tellers > 0 ) {
            $tellers =~ s/^\s*(\S+)\s+(\S+)\s*//;
            my ( $host, $port ) = ( $1, $2 );
            $NUM_VOTER_BBS = push( @VOTER_BB_HOSTS, $host );
            push( @VOTER_BB_PORTS, $port );
        }
    }
    if ( $NUM_VOTER_HOSTS == 0 ) {
        $NUM_VOTER_HOSTS = 1;
        @VOTER_HOSTS     = ("localhost");
    }
    if ( $NUM_TAB_TELLERS == 0 ) {
        debugprint("ERROR $expFile: at least one tabulaton teller must be specified\n");
        $failed = 1;
    }
    if ( $NUM_REG_TELLERS == 0 ) {
        debugprint("ERROR $expFile: at least one registration teller must be specified\n");
        $failed = 1;
    }
    if ( $NUM_VOTER_BBS == 0 ) {
        debugprint("ERROR $expFile: at least one voter bulletin board must be specified\n");
        $failed = 1;
    }
    if ($failed) {
        exit($failed);
    }
    
    # recalc the filenames based on the keylengths
    resetKeyFilenameVars();
    
    $LOCAL_DATA_DIR             = $LOCAL_DATA_DIR . "/" . getExperimentShortName();
    $CENTRAL_DATA_DIR           = $CENTRAL_DATA_DIR . "/" . getExperimentShortName();
    $electionID_file            = "$LOCAL_DATA_DIR/$electionID_file";
    $electionDetails_file       = "$CENTRAL_DATA_DIR/$electionDetails_file";
    $tellerDetails_file         = "$CENTRAL_DATA_DIR/$tellerDetails_file";
    $elGamalParams_file         = "$LOCAL_KEYS_DIR/$elGamalParams_file";
    $elGamalVoterKeyParams_file = "$LOCAL_KEYS_DIR/$elGamalVoterKeyParams_file";
    $bbPublicKey_file           = "$CENTRAL_KEYS_DIR/$bbPublicKey_file";
    $bbPrivateKey_file          = "$CENTRAL_KEYS_DIR/$bbPrivateKey_file";
    $regPublicKey_file          = "$LOCAL_KEYS_DIR/$regPublicKey_file";
    $regPrivateKey_file         = "$LOCAL_KEYS_DIR/$regPrivateKey_file";
    $supPublicKey_file          = "$LOCAL_KEYS_DIR/$supPublicKey_file";
    $supPrivateKey_file         = "$LOCAL_KEYS_DIR/$supPrivateKey_file";
}

END {
}

# utility routines
# execute a script on a particular machine.
# usage civitasRemoteExec(host, @args)
sub civitasRemoteExec {
    my @cmd      = @_;
    my $reqHost  = shift @cmd;
    my $thisHost = $ENV{'HOST'};
    if ( !defined $thisHost ) {
        $thisHost = "";
    }
    my $reqHostShortName = hostShortname($reqHost);
    if ( $reqHost eq 'localhost' || $thisHost eq $reqHost || $thisHost eq $reqHostShortName ) {

        # we are currently on the correct host
        civitasExec(@cmd);
    }
    else {

        # ssh to $reqHost, using the credentials $sshUser
        # and $sshIdentityFile, if given.
        my @sshCmd        = ("ssh");
        my $runBackground = 0;

        # escape special characters in the command, and determine if we
        # want to fork
        my @escCmd = ();
        foreach my $c (@cmd) {
            if ( $c eq '&' ) {
                $runBackground = 1;
                next;
            }
            $c =~ s/\'/\\\'/g;
            $c =~ s/\"/\\\"/g;
            push( @escCmd, $c );
        }
        if ($runBackground) {
            push( @sshCmd, '-f' );
        }
        if ( length($sshIdentityFile) > 0 ) {
            push( @sshCmd, '-i' );
            push( @sshCmd, $sshIdentityFile );
        }
        if ( length($sshUser) > 0 ) {
            push( @sshCmd, $sshUser . '@' . $reqHost );
        }
        else {
            push( @sshCmd, $reqHost );
        }
        civitasExec( @sshCmd, @escCmd );
    }
}

sub civitasExec {
    my @cmd = @_;
    system join( ' ', @cmd );
}

# copy a directory to a particular machine.
# usage civitasRemoteCopy(host, sourceDir, targetDir)
sub civitasRemoteCopy {
    my ( $reqHost, $sourceDir, $targetDir ) = @_;

    # scp $dir to $reqHost, using the credentials $sshUser
    # and $sshIdentityFile, if given.
    # scp -r -i idfile file user@host:file
    my @scpCmd = ( "scp", "-rq" );
    if ( length($sshIdentityFile) > 0 ) {
        push( @scpCmd, '-i' );
        push( @scpCmd, $sshIdentityFile );
    }
    push( @scpCmd, $sourceDir );
    if ( length($sshUser) > 0 ) {
        push( @scpCmd, $sshUser . '@' . $reqHost . ':' . $targetDir );
    }
    else {
        push( @scpCmd, $reqHost . ':' . $targetDir );
    }
    civitasExec(@scpCmd);
}

sub debugprint {
    print "[CIVITAS] $_[0]";
}

sub hostShortname {
    my ($host) = @_;
    my $hostShortName = $host;
    if ( $host =~ /[a-z]/ && $host =~ /^([^\.]+)\./ ) {
        $hostShortName = $1;
    }
    return $hostShortName;
}

sub experimentUniqueHosts {
    my %seenHosts = ();
    my @uniqHosts = ();
    foreach my $item ( @TAB_TELLER_HOSTS, @REG_TELLER_HOSTS, @VOTER_BB_HOSTS, $adminBBhost ) {
        push( @uniqHosts, $item ) unless $seenHosts{$item}++;
    }
    return @uniqHosts;
}

# Returns the results directory for an experiment description file.
# If arguments are given, they are used to construct a filename within the results directory
sub experimentResultsDir {
    my @ARGS   = @_;
    my $expdir = getExperimentShortName();

    # add the other args on
    if ( $#ARGS >= 0 ) {
        $expdir = $expdir . '/' . ( shift @ARGS );
        while ( $#ARGS >= 0 ) {
            $expdir = $expdir . '-' . ( shift @ARGS );
        }
    }
    return $results_dir . '/' . $expdir;
}

sub experimentTempResultsDir {
    my @ARGS   = @_;
    my $expdir = $LOCAL_DATA_DIR . '/tempResults';

    # add the other args on
    if ( $#ARGS >= 0 ) {
        $expdir = $expdir . '/' . ( shift @ARGS );
        while ( $#ARGS >= 0 ) {
            $expdir = $expdir . '-' . ( shift @ARGS );
        }
    }
    return $expdir;
}

sub getExperimentShortName() {
    my $expdir = $expFile;

    # just use the filename of the file
    $expdir =~ s/^.*\/([^\/]+)$/$1/;

    # cut off the suffix, if any
    $expdir =~ s/\.([^\.]+)$//;
    return $expdir;
}

# Creates all the given directory, including parent directories if needed.
sub createDirectory {
    my ($reqDir) = @_;
    my @rdirs = split( /\//, $reqDir );
    $reqDir = "";
    foreach my $d (@rdirs) {
        $reqDir = $reqDir . $d . '/';
        if ( !( -e $reqDir ) ) {
            die("$!") unless mkdir($reqDir);
        }
    }
}

sub BBFileRoot {
    my ( $host, $port ) = @_;
    my $hostShortName = hostShortname($host);
    return "$LOCAL_DATA_DIR/fileBBroot$hostShortName$port";
}
sub TabFileRoot {
    my ( $host, $port ) = @_;
    my $hostShortName = hostShortname($host);
    return "$LOCAL_DATA_DIR/fileTTRoot$hostShortName$port";
}
sub FileCacheRoot {
    my ( $host, $port ) = @_;
    my $hostShortName = hostShortname($host);
    return "$LOCAL_DATA_DIR/fileCacheRoot$hostShortName$port";
}

sub TabTellPublicKeyFile {
    return "$CENTRAL_KEYS_DIR/tabTellPublicKey$_[0]-$publicKeyLength.xml";
}

sub TabTellPrivateKeyFile {
    return "$CENTRAL_KEYS_DIR/tabTellPrivateKey$_[0]-$publicKeyLength.xml";
}

sub RegTellPublicKeyFile {
    return "$CENTRAL_KEYS_DIR/regTellPublicKey$_[0]-$publicKeyLength.xml";
}

sub RegTellPrivateKeyFile {
    return "$CENTRAL_KEYS_DIR/regTellPrivateKey$_[0]-$publicKeyLength.xml";
}

sub VoterBBPublicKeyFile {
    return "$CENTRAL_KEYS_DIR/voterBBPublicKey$_[0]-$publicKeyLength.xml";
}

sub VoterBBPrivateKeyFile {
    return "$CENTRAL_KEYS_DIR/voterBBPrivateKey$_[0]-$publicKeyLength.xml";
}

sub VoterPublicKeyFile {
    return "$LOCAL_KEYS_DIR/voterPublicKey$_[0]-$publicKeyLength.xml";
}

sub VoterPrivateKeyFile {
    return "$LOCAL_KEYS_DIR/voterPrivateKey$_[0]-$publicKeyLength.xml";
}
sub VoterEGPublicKeyFile {
    return "$LOCAL_KEYS_DIR/voterEGPublicKey$_[0]-$elGamalVoterKeyLength-$elGamalVoterGroupLength.xml";
}

sub VoterEGPrivateKeyFile {
    return "$LOCAL_KEYS_DIR/voterEGPrivateKey$_[0]-$elGamalVoterKeyLength-$elGamalVoterGroupLength.xml";
}

sub reportMissingParam {
    my ($key) = @_;
	debugprint("ERROR $expFile: no value given for $key.\n");
	
}
sub reportMissingOptParam {
    my ($key, $defaultVal) = @_;
	debugprint("WARNING $expFile: no value given for $key.\n");
	debugprint("WARNING $expFile:     using default value $defaultVal.\n");
}

sub findCivitasDir {
    # assume the script that is including us in the $CIVITAS/experiments/src directory
    my ($possDir) = ($FindBin::Bin)."/../..";
    return $possDir;  
}

resetVars();


1;    # ok!
