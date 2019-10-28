/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */ 
package civitas;

import java.io.*;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import jif.lang.Label;
import jif.lang.PrincipalUtil;
import until.lang.LabelUntilUtil;
import civitas.common.*;
import civitas.crypto.*;
import civitas.voter.Voter;

/**
 * Automated voting client, used in experiments to generate ballots and 
 * submit votes for many voters.
 * 
 */
public class AutomatedVotingClient {
    private static void usage() {
        System.err.println("Usage: AutomatedVotingClient electionDetails tellerDetails");
        System.err.println("                 indexmarker voterNameFormat voterEGPrivKeyFormat voterEGPubKeyFormat voterPrivKeyFormat voterPubKeyFormat");
        System.err.println("                 startIndex count dupCount invCount");
        System.err.println("                 finishFile cacheDir logfile");
        System.err.println("  yeah, it's a lot of arguments. Here's a quick explanation.");
        System.err.println("    electionDetails    : file containing election details");
        System.err.println("    tellerDetails      : file containing teller details");
        System.err.println("    indexmarker        : string that occurs in the following format args. e.g. VXX");
        System.err.println("    voterNameFormat    : format of voter names, where indexmarker is replaced with a number. e.g. voter_VXX");
        System.err.println("    voterEGPrivKeyFormat : format of voter's El Gamal private key filename, where indexmarker is replaced with a number. e.g. data/voterVXXPrivKey.xml");
        System.err.println("    voterEGPubKeyFormat  : format of voter's El Gamal public key filename, where indexmarker is replaced with a number. e.g. data/voterVXXPubKey.xml");
        System.err.println("    voterPrivKeyFormat : format of voter's private key filename, where indexmarker is replaced with a number. e.g. data/voterVXXPrivKey.xml");
        System.err.println("    voterPubKeyFormat  : format of voter's public key filename, where indexmarker is replaced with a number. e.g. data/voterVXXPubKey.xml");
        System.err.println("    startIndex         : the index of the voter that this client is to start from");
        System.err.println("    count              : the number of voters that this client will process, i.e. process from startIndex to startIndex+count-1");
        System.err.println("    dupCount           : the number of duplicate ballots to submit, i.e., repeat dupCount times: select voter from startIndex to startIndex+count-1, and submit another ballot using their credentials");
        System.err.println("    invCount           : the number of invalid ballots to submit, i.e., repeat invCount times: select voter from startIndex to startIndex+count-1, and submit a ballot in their name using false credentials");
        System.err.println("    cacheClientData    : Y, or 1, or true will cause cahcing of voter client data");
        System.err.println("    finishFile         : file to create when finished voting, as a simple mechanism to indicate completion");
        System.err.println("    cacheDir           : directory to use for caching data");
        System.err.println("    logfile            : file to log information to.");
        System.exit(0);        
    }
    public static void main(String[] args) {
        int i = 0;
        String electionDetails = args[i++];
        String tellerDetails = args[i++];
        String indexmarker = args[i++];
        String voterNameFormat = args[i++];
        String voterEGPrivKeyFormat = args[i++];
        String voterEGPubKeyFormat = args[i++];
        String voterPrivKeyFormat = args[i++];
        String voterPubKeyFormat = args[i++];
        int startIndex = Integer.parseInt(args[i++]);
        int count = Integer.parseInt(args[i++]);
        int dupCount = Integer.parseInt(args[i++]);
        int invCount = Integer.parseInt(args[i++]);
        String cacheClient = args[i++].toLowerCase();
        String finishFile = args[i++];
        String cacheDir = args[i++];
        String logfile  = args[i++];
        
        if (args.length != i) usage();

        boolean clientCaching = cacheClient.startsWith("y") || cacheClient.equals("true") || cacheClient.equals("1");
        try {
            new AutomatedVotingClient(new PrintWriter(logfile)).submitBallot(cacheDir,
                                                     electionDetails, tellerDetails, indexmarker,
                                                     voterNameFormat, 
                                                     voterEGPrivKeyFormat, voterEGPubKeyFormat, 
                                                     voterPrivKeyFormat, voterPubKeyFormat, 
                                                     startIndex, count, dupCount, invCount,
                                                     clientCaching);
        }
        catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        try {
            PrintStream fout = new PrintStream(new FileOutputStream(finishFile));
            fout.println("done");
            fout.close();
        }
        catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    /**
     * logfile is used to record some usage statistics.
     */
    private final PrintWriter logfile;
    public AutomatedVotingClient(PrintWriter logfile) {
        this.logfile = logfile;
    }


    private void submitBallot(String cacheDir, String electionDetailsFile,
            String tellerDetailsFile, String indexmarker, String voterNameFormat,
            String voterEGPrivKeyFormat, String voterEGPubKeyFormat,
            String voterPrivKeyFormat_, String voterPubKeyFormat_,
            int voterStartIndex, int count, int dupCount, int invCount,
            boolean cacheClient) throws IllegalArgumentException, IOException {
        ElectionDetails electionDetails = ElectionDetails.fromXML(LabelUntilUtil.singleton().noComponents(), 
                                                                  new BufferedReader(new FileReader(electionDetailsFile)));

        ElectionCache electionCache = null;
        if (cacheClient) {
            electionCache = new FileBasedElectionCache(cacheDir, electionDetails.electionID.id);
        }
        TellerDetails tellerDetails = TellerDetails.fromXML(LabelUntilUtil.singleton().noComponents(), 
                                                            new BufferedReader(new FileReader(tellerDetailsFile)));
        electionCache.setElectionDetails(electionDetails);
        electionCache.setTellerDetails(tellerDetails);
        
        
        int numVoterBlocks = ElectionUtil.numberVoterBlocks(electionDetails, electionCache);

        int voterEndIndex = voterStartIndex + count;

        // choose dupCount voters (with replacement) to vote again.
        Map<Integer, Integer> dupVoters = new HashMap<Integer, Integer>();
        Random rand = new SecureRandom(electionDetailsFile.getBytes());
        for (int i = 0 ; i < dupCount; i++) {
            // choose a voter index ind, voterStartIndex <= ind < voterEndIndex
            int ind = rand.nextInt(count) + voterStartIndex;
            if (dupVoters.containsKey(ind)) {
                dupVoters.put(ind, dupVoters.get(ind)+1);
            }
            else {
                dupVoters.put(ind, 1);                
            }
        }
        
        long startTime = System.currentTimeMillis();
        long totalRetrieveCaps = 0;
        long totalSubmissionTime = 0;
        long totalDupSubmissionTime = 0;
        long totalInvSubmissionTime = 0;

        for (int i = voterStartIndex; i < voterEndIndex; i++) {
            String voterIndexS = Integer.toString(i);
            String voterName = voterNameFormat.replaceAll(indexmarker, voterIndexS);
            String voterEGPrivKeyFile = voterEGPrivKeyFormat.replaceAll(indexmarker, voterIndexS);
            String voterEGPubKeyFile = voterEGPubKeyFormat.replaceAll(indexmarker, voterIndexS);
            String voterPrivKeyFile = voterPrivKeyFormat_.replaceAll(indexmarker, voterIndexS);
            String voterPubKeyFile = voterPubKeyFormat_.replaceAll(indexmarker, voterIndexS);

            ElGamalPublicKey voterEGPubKey = CryptoUtil.factory().egPubKeyFromFile(voterEGPubKeyFile);
            ElGamalPrivateKey voterEGPrivKey = CryptoUtil.factory().egPrivKeyFromFile(voterEGPrivKeyFile);
            PublicKey voterPubKey = CryptoUtil.factory().publicKeyFromFile(voterPubKeyFile);
            PrivateKey voterPrivKey = CryptoUtil.factory().privateKeyFromFile(voterPrivKeyFile);
            try {
                long beforeRetrieveCaps = System.currentTimeMillis();
                VoterCapabilities vc = Voter.retrieveCapabilities(electionCache,
                                                                  electionDetails,
                                                                  tellerDetails,
                                                                  voterName,
                                                                  voterEGPubKey,
                                                                  voterEGPrivKey,
                                                                  voterPubKey,
                                                                  voterPrivKey);
                
                long afterRetrieveCaps = System.currentTimeMillis();
                totalRetrieveCaps += (afterRetrieveCaps - beforeRetrieveCaps);
                
                Ballot ballot = GenerateTestFiles.generateBallot(null, electionDetails.ballotDesign, voterName.getBytes());

                // System.err.println("gen  "  + (start2 - start));
                long beforeSubmission = System.currentTimeMillis();
                Voter.vote(PrincipalUtil.bottomPrincipal(), GenerateTestFiles.voterBlockForVoter(i, numVoterBlocks), electionDetails, electionCache, ballot, vc.capabilities);
                long afterSubmission = System.currentTimeMillis();
                
                totalSubmissionTime += (afterSubmission - beforeSubmission);
                
                // do we need to submit duplicate votes for the voter?
                int dupSubs = 0;
                if (dupVoters.containsKey(i)) {
                    dupSubs = dupVoters.get(i);
                }
                for (int j = 0; j < dupSubs; j++) {
                    Ballot dupBallot = GenerateTestFiles.generateBallot(null, electionDetails.ballotDesign, (voterName+"dup").getBytes());
                    
                    long beforeDupSubmission = System.currentTimeMillis();
                    Voter.vote(PrincipalUtil.bottomPrincipal(), voterName, electionDetails, electionCache, dupBallot, vc.capabilities);                    
                    long afterDupSubmission = System.currentTimeMillis();
                    totalDupSubmissionTime += (afterDupSubmission - beforeDupSubmission);
                }
            }
            catch (CryptoException e) {
                e.printStackTrace();
            }

        }
        
        // now submit the invalid ballots
        for (int i = 0; i < invCount; i++) {
            int voterBlock = rand.nextInt(ElectionUtil.numberVoterBlocks(electionDetails, electionCache));

            VoterCapabilities vc = GenerateTestFiles.generateFakeCapabilities(electionDetails, voterBlock);
            Ballot ballot = GenerateTestFiles.generateBallot(null, electionDetails.ballotDesign);
            long beforeInvSubmission = System.currentTimeMillis();
            Voter.vote(null, voterBlock, electionDetails, electionCache, ballot, vc.capabilities);                         
            long afterInvSubmission = System.currentTimeMillis();
            totalInvSubmissionTime += (afterInvSubmission - beforeInvSubmission);
        }
        long endTime = System.currentTimeMillis();
        // now log some output.
        logfile.println("numberOfVoters : " + count);
        logfile.println("voterStartIndex : " + voterStartIndex);
        logfile.println("voterEndIndex : " + voterEndIndex);
        logfile.println("totalElapsedTime : " + (endTime-startTime));
        logfile.println("totalCapabilityRetrieveTime : " + totalRetrieveCaps);
        logfile.println("totalSubmissionTime : " + totalSubmissionTime);
        logfile.println("totalDupSubmissionTime : " + totalDupSubmissionTime);
        logfile.println("totalInvSubmissionTime : " + totalInvSubmissionTime);
        logfile.println("grandTotalSubmissionTime : " + (totalSubmissionTime + totalDupSubmissionTime + totalInvSubmissionTime));
        logfile.close();

    }
}