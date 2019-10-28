#!/usr/bin/perl
# CIVITAS
#
# This script generates keys.

use FindBin;                # where is this script installed?
use lib $FindBin::Bin;      # include this directory in the library search path
use File::Copy;
use Civitas::Experiments;
use strict;
use warnings;

sub usage {
    print <<USAGE;
usage: generateKeys.pl experimentDescriptionFile [-generate]
    Generates keys for an election. If -generate is specified,
    new keys will be created as needed, otherwise a complaint will
    be generated.
USAGE
    exit;
}
if ( $#ARGV > 1 || $#ARGV < 0 ) {
    usage();
}
initExp( $ARGV[0] );
my $generate = 0;
if ( $#ARGV == 1 ) {
    $generate = ( $ARGV[1] eq '-generate' );
    usage() unless ($generate);
}

# create the keys directories if needed
if ( !( -e $CENTRAL_KEYS_DIR ) ) {
    createDirectory($CENTRAL_KEYS_DIR);
}
if ( !( -e $LOCAL_KEYS_DIR ) ) {
    createDirectory($LOCAL_KEYS_DIR);

    # copy the keys over
    system("cp $CENTRAL_KEYS_DIR/*.xml $LOCAL_KEYS_DIR");
}

# check for the el gamal params
if ( !( -e "$elGamalParams_file" ) || -z "$elGamalParams_file" ) {
    if ($generate) {
        debugprint "Generating El Gamal parameters\n";
        `$CIVITAS/bin/civitasrun civitas.GenerateTestFiles egparams $elGamalParams_file $elGamalKeyLength $elGamalGroupLength`;
    }
    else {
        die("Couldn't find El Gamal parameters file $elGamalParams_file. Stopped");
    }
}

# generate voter el gamal params
if ( !( -e "$elGamalVoterKeyParams_file" ) || -z "$elGamalVoterKeyParams_file" ) {
    if ($generate) {
        debugprint "Generating voters' El Gamal parameters\n";
        `$CIVITAS/bin/civitasrun civitas.GenerateTestFiles egparams $elGamalVoterKeyParams_file $elGamalVoterKeyLength $elGamalVoterGroupLength`;
    }
    else {
        die("Couldn't find El Gamal voter's parameters file $elGamalVoterKeyParams_file. Stopped");
    }
}

# generate public and private keys
my %keysToGen = ();
$keysToGen{"$bbPublicKey_file"}  = "$bbPrivateKey_file";
$keysToGen{"$supPublicKey_file"} = "$supPrivateKey_file";
$keysToGen{"$regPublicKey_file"} = "$regPrivateKey_file";
for ( my $count = 1 ; $count <= $NUM_TAB_TELLERS ; $count++ ) {
    my $tabPubKey_file  = TabTellPublicKeyFile($count);
    my $tabPrivKey_file = TabTellPrivateKeyFile($count);
    $keysToGen{"$tabPubKey_file"} = "$tabPrivKey_file";
}
for ( my $count = 1 ; $count <= $NUM_REG_TELLERS ; $count++ ) {
    my $regPubKey_file  = RegTellPublicKeyFile($count);
    my $regPrivKey_file = RegTellPrivateKeyFile($count);
    $keysToGen{"$regPubKey_file"} = "$regPrivKey_file";
}
for ( my $count = 1 ; $count <= $NUM_VOTER_BBS ; $count++ ) {
    my $vbbPubKey_file  = VoterBBPublicKeyFile($count);
    my $vbbPrivKey_file = VoterBBPrivateKeyFile($count);
    $keysToGen{"$vbbPubKey_file"} = "$vbbPrivKey_file";
}
while ( my ( $pubKey, $privKey ) = each(%keysToGen) ) {
    if ( !( -e "$pubKey" ) ) {
        if ($generate) {
            debugprint "Generating key pair $pubKey $privKey\n";
            `$CIVITAS/bin/civitasrun civitas.GenerateTestFiles keys $publicKeyLength $pubKey $privKey`;
        }
        else {
            die("Couldn't find key $pubKey. Stopped");
        }
    }
}

# generate voter EG keys
%keysToGen = ();
for ( my $count = 1 ; $count <= $NUM_VOTERS ; $count++ ) {
    my $vPubKey_file  = VoterEGPublicKeyFile($count);
    my $vPrivKey_file = VoterEGPrivateKeyFile($count);
    $keysToGen{"$vPubKey_file"} = "$vPrivKey_file";
}
while ( my ( $pubKey, $privKey ) = each(%keysToGen) ) {
    if ( !( -e "$pubKey" ) || -z "$pubKey" ) {
        if ($generate) {
            debugprint "Generating key pair $pubKey $privKey\n";
            `$CIVITAS/bin/civitasrun civitas.GenerateTestFiles egkeys $elGamalVoterKeyParams_file $pubKey $privKey`;
        }
        else {
            die("Couldn't find key $pubKey. Stopped");
        }
    }
}

# generate voter RSA keys
%keysToGen = ();
for ( my $count = 1 ; $count <= $NUM_VOTERS ; $count++ ) {
    my $vPubKey_file  = VoterPublicKeyFile($count);
    my $vPrivKey_file = VoterPrivateKeyFile($count);
    $keysToGen{"$vPubKey_file"} = "$vPrivKey_file";
}
while ( my ( $pubKey, $privKey ) = each(%keysToGen) ) {
    if ( !( -e "$pubKey" ) || -z "$pubKey" ) {
        if ($generate) {
            debugprint "Generating key pair $pubKey $privKey\n";
            `$CIVITAS/bin/civitasrun civitas.GenerateTestFiles keys $publicKeyLength $pubKey $privKey`;
        }
        else {
            die("Couldn't find key $pubKey. Stopped");
        }
    }
}
