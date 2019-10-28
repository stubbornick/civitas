/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */ 
package civitas;

import java.io.*;

import jif.lang.JifObjectWrapper;
import jif.lang.LabelUtil;
import jif.util.HashMap;
import jif.util.List;
import jif.util.Map;
import until.lang.LabelUntilUtil;
import civitas.common.*;
import civitas.crypto.*;


/**
 * Some simple tests of the voter code.
 *
 */
public class VoterTest {
    public static void main(String[] args) {
        int voterBlock = 2;
        String[] candidates1 = {"Fred", "Wil\"ma", "Barney" }; 
        SingleChoiceBallotDesign bd1 = new SingleChoiceBallotDesign().civitas$common$SingleChoiceBallotDesign$(LabelUtil.singleton().noComponents(), candidates1);
        int capsNeeded = bd1.votesProducedPerBallot();

        SingleChoiceBallot b1 = new SingleChoiceBallot(LabelUtil.singleton().noComponents()).civitas$common$SingleChoiceBallot$(candidates1[0]);

        StringWriter sw = new StringWriter();
        b1.toXML(new PrintWriter(sw));
        System.out.println("Ballot is now " + sw.toString());

        SingleChoiceBallot temp1 = b1;

        sw = new StringWriter();
        temp1.toXML(new PrintWriter(sw));
        try {
            b1 = (SingleChoiceBallot)Ballot.fromXML(LabelUtil.singleton().noComponents(),
                                                                LabelUtil.singleton().noComponents(),
                                                                new StringReader(sw.toString()));
        }
        catch (IllegalArgumentException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        sw = new StringWriter();
        b1.toXML(new PrintWriter(sw));
        System.out.println("Ballot is now " + sw.toString());
        ElGamalParameters params = CryptoUtil.factory().generateElGamalParameters();

        Map caps = new HashMap(LabelUntilUtil.singleton().noComponents(),LabelUntilUtil.singleton().noComponents()).jif$util$HashMap$();
        List contexts = bd1.contextsNeeded(LabelUntilUtil.singleton().noComponents(), "base");
        
        VoteCapabilityShare[][] shares = new VoteCapabilityShare[1][capsNeeded];
        for (int i = 0; i < capsNeeded; i++) {                
            shares[0][i] = CryptoUtil.factory().generateVoteCapabilityShare(params);
        }
        VoteCapability[] capabilities = CryptoUtil.factory().combineVoteCapabilityShares(LabelUntilUtil.singleton().noComponents(),
                                                         shares, params);

        for (int i = 0; i < capabilities.length; i++) {                
            caps.put(contexts.get(i), new JifObjectWrapper(LabelUntilUtil.singleton().noComponents()).jif$lang$JifObjectWrapper$(capabilities[i]));
        }
        
        
        
        ElGamalKeyPair kp = CryptoUtil.factory().generateElGamalKeyPair(params);
        ElGamalCiphertext[] ciphertexts = CryptoUtil.factory().constructWellKnownCiphertexts(LabelUtil.singleton().noComponents(), kp.publicKey(), bd1.maxPossibleChoices());
        VoterSubmission vs = bd1.decompose(LabelUtil.singleton().noComponents(), 
                                           b1, voterBlock, 
                                           kp.publicKey(), 
                                           ciphertexts, 
                                           "base", 
                                           caps);
        
        bd1.checkBallot(LabelUtil.singleton().noComponents(), b1);
        bd1.checkVoterSubmission(vs, "base", new CiphertextList().civitas$common$CiphertextList$(LabelUtil.singleton().noComponents(), ciphertexts), kp.publicKey());

        System.out.println("candidate of choice is " + b1.candidate); 
        StringWriter sb = new StringWriter();
        b1.toXML(new PrintWriter(sb));
        System.out.println("ballot xml is " + sb.toString()); 
        System.out.println("vs votes.length is " + vs.votes.length); 

        sb = new StringWriter();
        vs.toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        System.out.println("VoterSubmission is " + sb.toString());
    }
 }
