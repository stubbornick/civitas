/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */
package civitas;

import java.io.*;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import jif.lang.Label;
import jif.lang.LabelUtil;
import civitas.common.*;
import civitas.crypto.*;


/**
 * Utility methods to generate test files.
 */
public class GenerateTestFiles {
    private static SecureRandom rand = new SecureRandom();
    public static void main(String[] args) {
        try {
            parseCommandLine(args);
        }
        finally {
            System.err.flush();
        }
    }
    private static void parseCommandLine(String[] args) {
        if (args.length == 0) {
            System.err.println("usage: cmd [options]");
            System.err.println("   cmd is one of keys, egparams, egkeys, electionDetails, tellerDetails, electoralRoll, ballot");
            return;
        }
        String cmd = args[0];
        if (cmd.equalsIgnoreCase("keys")) {
            try {
                int keyLength = Integer.parseInt(args[1]);
                PrintStream publicKeyOut = new PrintStream(new FileOutputStream(args[2]));
                PrintStream privateKeyOut = new PrintStream(new FileOutputStream(args[3]));
                generateKeyPair(keyLength, publicKeyOut, privateKeyOut, System.err);
            }
            catch (FileNotFoundException e) {
                System.err.println(e.getMessage());
            }
            catch (RuntimeException e) {
                System.err.println("usage: keys inKeyLength outPublicKeyFile outPrivateKeyFile");
                return;
            }
        }
        else if (cmd.equalsIgnoreCase("egparams")) {
            try {
                PrintStream paramsOut = new PrintStream(new FileOutputStream(args[1]));
                ElGamalParameters params = null;
                if (args.length > 2) {
                    params = CryptoUtil.factory().generateElGamalParameters(Integer.parseInt(args[2]), Integer.parseInt(args[3]));
                }
                else {
                    params = CryptoUtil.factory().generateElGamalParameters();
                }
                Label lbl = LabelUtil.singleton().noComponents();
                StringWriter sb = new StringWriter();
                params.toXML(lbl, new PrintWriter(sb));
                paramsOut.println(sb.toString());
                paramsOut.close();
            }
            catch (RuntimeException e) {
                return;
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
        else if (cmd.equalsIgnoreCase("egkeys")) {
            try {
                ElGamalParameters params = CryptoUtil.factory().elGamalParametersFromXML(LabelUtil.singleton().noComponents(), new BufferedReader(new FileReader(args[1])));
                PrintStream publicKeyOut = new PrintStream(new FileOutputStream(args[2]));
                PrintStream privateKeyOut = new PrintStream(new FileOutputStream(args[3]));
                generateElGamalKeyPair(publicKeyOut, privateKeyOut, System.err, params);
            }
            catch (RuntimeException e) {
                System.err.println("usage: egkeys inElGamalParameters outPublicKeyFile outPrivateKeyFile");
                return;
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
        else if (cmd.equalsIgnoreCase("electionDetails")) {
            try {
                int i = 1;
                ElectionID electionID = ElectionID.fromXML(LabelUtil.singleton().noComponents(), new BufferedReader(new FileReader(args[i++]))) ;
                PublicKey supPublicKey = CryptoUtil.factory().publicKeyFromFile(args[i++]);
                PublicKey regPublicKey = CryptoUtil.factory().publicKeyFromFile(args[i++]);

                ElGamalParameters params = CryptoUtil.factory().elGamalParametersFromXML(LabelUtil.singleton().noComponents(), new BufferedReader(new FileReader(args[i++])));
                int sharedKeyLength = Integer.parseInt(args[i++]);
                int voterAnonimity = Integer.parseInt(args[i++]);
                int nonceBitLength = Integer.parseInt(args[i++]);
                PrintStream detailsOut = new PrintStream(new FileOutputStream(args[i++]));
                generateElectionDetails(detailsOut, System.err, electionID, supPublicKey, regPublicKey, params, sharedKeyLength, voterAnonimity, nonceBitLength);

            }
            catch (NumberFormatException e) {
                System.err.println("usage: electionDetails inElectionID.xml inSupPublicKey.xml inRegPublicKey.xml inElGamalParams.xml inSharedKeyLength inVoterAnonymity inNonceBitLength outElectionDetails.xml");
                return;
            }
            catch (ArrayIndexOutOfBoundsException e) {
                System.err.println("usage: electionDetails inElectionID.xml inSupPublicKey.xml inRegPublicKey.xml inElGamalParams.xml inVoterAnonymity inNonceBitLength outElectionDetails.xml");
                return;
            }
            catch (IOException e) {
                e.printStackTrace();
                return;
            }
        }
        else if (cmd.equalsIgnoreCase("tellerDetails")) {
            try {
                PrintStream detailsOut = new PrintStream(new FileOutputStream(args[1]));

                List<Host> tabTellerHosts = new ArrayList<Host>();
                List<Host> regTellerHosts = new ArrayList<Host>();
                List<Host> voterBBHosts = new ArrayList<Host>();

                int ind = 1;
                while (++ind < args.length) {
                    List<Host> hostList;
                    if (args[ind].equals("-reg")) {
                        hostList = regTellerHosts;
                    }
                    else if (args[ind].equals("-tab")) {
                        hostList = tabTellerHosts;
                    }
                    else if (args[ind].equals("-bb")) {
                        hostList = voterBBHosts;
                    }
                    else {
                        throw new IllegalArgumentException("Unknown switch '" + args[ind] + "'");
                    }
                    String address = args[++ind];
                    String port = args[++ind];
                    String keyFile = args[++ind];
                    PublicKey key = CryptoUtil.factory().publicKeyFromFile(keyFile);
                    Host h = new Host().civitas$common$Host$(address, Integer.parseInt(port), key);
                    hostList.add(h);
                }

                generateTellerDetails(detailsOut, System.err, tabTellerHosts, regTellerHosts, voterBBHosts);
            }
            catch (RuntimeException e) {
                System.err.println("usage: tellerDetails outTellerDetails.xml ([-reg|-tab|-bb] address port inPublicKeyFile.xml)*");
                e.printStackTrace();
                return;
            }
            catch (IOException e) {
                e.printStackTrace();
                return;
            }
        }
        else if (cmd.equalsIgnoreCase("electoralRoll")) {
            try {
                PrintStream detailsOut = new PrintStream(new FileOutputStream(args[1]));
                ElectionDetails electionDetails = ElectionDetails.fromXML(LabelUtil.singleton().noComponents(), new BufferedReader(new FileReader(args[2])));
                ElectionCache electionCache = new ElectionCache().civitas$common$ElectionCache$();
                electionCache.setElectionDetails(electionDetails);

                List<ElGamalPublicKey> voterEGPublicKeys = new ArrayList<ElGamalPublicKey>();
                List<PublicKey> voterPublicKeys = new ArrayList<PublicKey>();

                for (int i = 3; i < args.length; ) {
                    voterEGPublicKeys.add(CryptoUtil.factory().egPubKeyFromFile(args[i++]));
                    voterPublicKeys.add(CryptoUtil.factory().publicKeyFromFile(args[i++]));
                }
                ElGamalPublicKey ttSharedKey = ElectionUtil.retrieveTabTellerSharedPublicKey(electionDetails, electionCache);
                int numberVoterBlocks = ElectionUtil.numberVoterBlocks(electionDetails, electionCache);
                generateElectoralRoll(detailsOut, System.err, voterEGPublicKeys, voterPublicKeys, numberVoterBlocks, ttSharedKey);
            }
            catch (RuntimeException e) {
                System.err.println("usage: electoralRoll outElectoralRoll.xml inElectionDetails.xml inVoterPublicKey.xml outVoterCapabilities.txt inVoterPublicKey.xml  outVoterCapabilities.txt ...");
                return;
            }
            catch (IOException e) {
                e.printStackTrace();
                return;
            }
        }
        else if (cmd.equalsIgnoreCase("ballot")) {
            try {
                ElectionDetails electionDetails = ElectionDetails.fromXML(LabelUtil.singleton().noComponents(), new BufferedReader(new FileReader(args[1])));
                generateBallot(args[2], System.err, electionDetails);
            }
            catch (RuntimeException e) {
                System.err.println("usage: ballot inElectionDetails.xml outBallot.xml");
                return;
            }
            catch (IOException e) {
                e.printStackTrace();
                return;
            }
        }
        else if (cmd.equalsIgnoreCase("fakeCapabilities")) {
            try {
                String voterName = args[1];
                ElectionDetails electionDetails = ElectionDetails.fromXML(LabelUtil.singleton().noComponents(),
                                                                          new BufferedReader(new FileReader(args[2])));
                PrintStream capsOut = new PrintStream(new FileOutputStream(args[3]));
                rand.setSeed(args[3].getBytes());
                ElectionCache electionCache = new ElectionCache().civitas$common$ElectionCache$();
                electionCache.setElectionDetails(electionDetails);

                generateFakeCapabilities(capsOut, System.err, electionDetails, ElectionUtil.retrieveVotersBlock(electionCache, electionDetails, voterName));
            }
            catch (RuntimeException e) {
                System.err.println("usage: fakeCapabilities voterName inElectionDetails.xml outVoterFakeCapabilities.xml");
                return;
            }
            catch (IOException e) {
                e.printStackTrace();
                return;
            }
        }
    }

    public static KeyPair generateKeyPair(int keyLength, PrintStream pubKeyOutput, PrintStream privKeyOutput, PrintStream console) {
        Label lbl = LabelUtil.singleton().noComponents();
        KeyPair kp = CryptoUtil.factory().generateKeyPair(keyLength);

        StringWriter sb = new StringWriter();
        kp.privateKey.toXML(lbl, new PrintWriter(sb));
        privKeyOutput.println(sb.toString());
        sb = new StringWriter();
        kp.publicKey.toXML(lbl, new PrintWriter(sb));
        pubKeyOutput.println(sb.toString());

        return kp;

    }
    public static ElGamalKeyPair generateElGamalKeyPair(PrintStream pubKeyOutput, PrintStream privKeyOutput, PrintStream console, ElGamalParameters params) {
        ElGamalKeyPair kp = CryptoUtil.factory().generateElGamalKeyPair(params);
        Label lbl = LabelUtil.singleton().noComponents();
        StringWriter sb = new StringWriter();
        kp.privateKey().toXML(lbl, new PrintWriter(sb));
        privKeyOutput.println(sb.toString());
        sb = new StringWriter();
        kp.publicKey().toXML(lbl, new PrintWriter(sb));
        pubKeyOutput.println(sb.toString());

        return kp;

    }
    public static void generateElectionDetails(PrintStream output, PrintStream console,
            ElectionID electionID,
            PublicKey supPubKey,
            PublicKey regPubKey,
            ElGamalParameters params,
            int sharedKeyLength,
            int voterAnonymity,
            int nonceBitLength) {
        String[] candidates1 = {"Fred", "Wilma", "Barney" };
        SingleChoiceBallotDesign bd1 = new SingleChoiceBallotDesign().civitas$common$SingleChoiceBallotDesign$(LabelUtil.singleton().noComponents(), candidates1);

//        String[] candidates2 = {"Homer", "Marje", "Barney" };
//        ApprovalBallotDesign bd2 = new ApprovalBallotDesign().civitas$common$ApprovalBallotDesign$(LabelUtil.singleton().noComponents(), candidates2);
//
//        String[] candidates3 = {"George", "Elroy", "Jane" };
//        CondorcetBallotDesign bd3 = new CondorcetBallotDesign().civitas$common$CondorcetBallotDesign$(LabelUtil.singleton().noComponents(), candidates3);
//
//
//        BallotDesign[] designs = {bd2, bd1};
//        MultiBallotDesign mbd = new MultiBallotDesign().civitas$common$MultiBallotDesign$(LabelUtil.singleton().noComponents(), designs);

        BallotDesign bd = bd1;

        ElectionDetails ed = new ElectionDetails().civitas$common$ElectionDetails$(
                                                                                electionID,
                                                                                supPubKey,
                                                                                regPubKey,
                                                                                "name",
                                                                                "description<>",
                                                                                Util.currentVersion(),
                                                                                bd,
                                                                                "noon",
                                                                                "1pm",
                                                                                "2pm",
                                                                                params,
                                                                                sharedKeyLength,
                                                                                (nonceBitLength/8),
                                                                                voterAnonymity);

        StringWriter sb = new StringWriter();
        ed.toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        String s = sb.toString();
        output.println(s);
        // check parsing
        try {
            ElectionDetails.fromXML(LabelUtil.singleton().noComponents(), new StringReader(s));
        }
        catch (IllegalArgumentException e) {
            e.printStackTrace(console);
        }
        catch (IOException e) {
            e.printStackTrace(console);
        }
    }

    public static void generateTellerDetails(PrintStream output, PrintStream console,
            List<Host> tabHosts,
            List<Host> regHosts,
            List<Host> voterBBHosts) {
        Host[] tabTellers = tabHosts.toArray(new Host[0]);
        Host[] regTellers = regHosts.toArray(new Host[0]);
        Host[] voterBBs = voterBBHosts.toArray(new Host[0]);
        TellerDetails td = new TellerDetails().civitas$common$TellerDetails$(LabelUtil.singleton().noComponents(), regTellers, tabTellers, voterBBs);

        StringWriter sb = new StringWriter();
        td.toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        output.println(sb.toString());
    }

    /**
     * Return the voter block for the given voter index. The voter index should between 1 and numVoters inclusive
     * @param voterIndex
     * @param numVoterBlocks
     * @return
     */
    public static int voterBlockForVoter(int voterIndex, int numVoterBlocks) {
        return (voterIndex-1) % numVoterBlocks;
    }
    public static void generateElectoralRoll(PrintStream output, PrintStream console,
            List<ElGamalPublicKey> egPublicKeys,
            List<PublicKey> publicKeys,
            int numVoterBlocks,
            ElGamalPublicKey tabTellerPK) {
        VoterDetails[] vds = new VoterDetails[egPublicKeys.size()];
        int i = 0;
        if (egPublicKeys.size() != publicKeys.size()) {
            throw new RuntimeException("Different number of el gamal and public keys!");
        }
        Iterator<ElGamalPublicKey> egKeysIter = egPublicKeys.iterator();
        Iterator<PublicKey> keysIter = publicKeys.iterator();
        while (egKeysIter.hasNext()) {
            ElGamalPublicKey egKey = egKeysIter.next();
            PublicKey key = keysIter.next();
            int voterBlock = voterBlockForVoter(i+1, numVoterBlocks);
            vds[i++] = new VoterDetails().civitas$common$VoterDetails$("Voter " + i,
                                                                    egKey,
                                                                    key,
                                                                    voterBlock);
        }

        ElectoralRoll er = new ElectoralRoll().civitas$common$ElectoralRoll$(vds);
        StringWriter sb = new StringWriter();
        er.toXML(new PrintWriter(sb));
        output.println(sb.toString());
    }

    public static void generateBallot(String outputfilename, PrintStream console, String electionDetails) throws IllegalArgumentException, IOException {
        ElectionDetails d = ElectionDetails.fromXML(LabelUtil.singleton().noComponents(), new BufferedReader(new FileReader(electionDetails)));
        generateBallot(outputfilename, console, d);
    }
    public static void generateBallot(String outputfilename, PrintStream console, ElectionDetails d) throws FileNotFoundException {
        PrintStream ballotOut = new PrintStream(new FileOutputStream(outputfilename));
        rand.setSeed(outputfilename.getBytes());
        generateBallot(ballotOut, console, d);
    }
    public static void generateBallot(PrintStream output, PrintStream console, ElectionDetails d) {
        Ballot b = generateBallot(console, d.ballotDesign);
        StringWriter sb = new StringWriter();
        b.toXML(new PrintWriter(sb));
        output.println(sb.toString());
    }
    public static Ballot generateBallot(PrintStream console, BallotDesign bd, byte[] seed) {
        rand.setSeed(seed);
        return generateBallot(console, bd);
    }
    public static Ballot generateBallot(PrintStream console, BallotDesign bd) {
        if (bd instanceof MultiBallotDesign) {
            MultiBallotDesign d = (MultiBallotDesign)bd;
            MultiBallot b = new MultiBallot(LabelUtil.singleton().noComponents()).civitas$common$MultiBallot$();
            for (int i = 0; i < d.designs.length; i++) {
                b.addBallot(generateBallot(console, d.designs[i]));
            }
            return b;
        }
        else if (bd instanceof SingleChoiceBallotDesign) {
            SingleChoiceBallotDesign d = (SingleChoiceBallotDesign)bd;
            int n = d.candidates.length;
            int choiceInd = rand.nextInt(n);
            String choice = d.candidates[choiceInd];
            if (console != null) console.println("Creating single choice ballot:  "+ choiceInd + " " + choice);
            return new SingleChoiceBallot(LabelUtil.singleton().noComponents()).civitas$common$SingleChoiceBallot$(choice);
        }
        else if (bd instanceof ApprovalBallotDesign) {
            ApprovalBallotDesign d = (ApprovalBallotDesign)bd;
            ApprovalBallot a = new ApprovalBallot(LabelUtil.singleton().noComponents()).civitas$common$ApprovalBallot$();
            if (console != null) console.println("Creating approval ballot");
            for (int i = 0; i < d.candidates.length; i++) {
                boolean b = rand.nextBoolean();
                a.addCandidate(d.candidates[i], b);
                if (console != null) console.println("  " + i + " " + d.candidates[i] + " approved? " + b);
            }
            return a;
        }
        else if (bd instanceof CondorcetBallotDesign) {
            CondorcetBallotDesign d = (CondorcetBallotDesign)bd;
            // assign the candidates a random rank
            if (console != null) console.println("Creating condorcet ballot");
            int[] rank = new int[d.numberOfCandidates()];
            for (int i = 0; i < rank.length; i++) {
                rank[i] = rand.nextInt(2*rank.length);
                if (console != null) console.println("  " + i + " " + d.candidates[i] + " rank is " + rank[i]);
            }
            CondorcetBallot a = new CondorcetBallot(LabelUtil.singleton().noComponents()).civitas$common$CondorcetBallot$(d.numberOfCandidates());

            for (int i = 0; i < d.numberOfCandidates(); i++) {
                for (int j = i + 1; j < d.numberOfCandidates(); j++) {
                    if (rank[i] < rank[j]) {
                        a.record(i, j, CondorcetBallotDesign.VOTE_CHOICE_I_BEATS_J);
                    }
                    else if (rank[i] > rank[j]) {
                        a.record(i, j, CondorcetBallotDesign.VOTE_CHOICE_J_BEATS_I);
                    }
                    else {
                        a.record(i, j, CondorcetBallotDesign.VOTE_CHOICE_NEITHER_BEAT);
                    }
                }
            }
            return a;
        }
        else {
            if (console != null) console.println("Sorry, the test file generation code cannot deal with ballot designs of class " + bd.getClass().getName() + " yet");
            return null;
        }
    }
    public static void generateFakeCapabilities(PrintStream output, PrintStream console, ElectionDetails d, int voterBlock) {
        VoterCapabilities vc = generateFakeCapabilities(d, voterBlock);
        StringWriter sb = new StringWriter();
        vc.toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        output.println(sb.toString());
    }
    public static VoterCapabilities generateFakeCapabilities(ElectionDetails d, int voterBlock) {
        int size = d.ballotDesign.votesProducedPerBallot();
        CryptoFactory f = CryptoUtil.factory();
        VoteCapabilityShare[][] shares = new VoteCapabilityShare[1][size];
        for (int i = 0; i < size; i++) {
            shares[0][i] = f.generateVoteCapabilityShare(d.elGamalParameters);
        }
        VoteCapability[] caps = f.combineVoteCapabilityShares(LabelUtil.singleton().noComponents(),
                                                              shares,
                                                              d.elGamalParameters);
        VoterCapabilities vc = new VoterCapabilities().civitas$common$VoterCapabilities$(caps , voterBlock);
        return vc;
    }

}