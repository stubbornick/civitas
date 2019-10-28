/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */ 
package civitas;

import java.io.*;

import jif.lang.LabelUtil;
import civitas.common.*;
import civitas.crypto.CryptoUtil;
import civitas.crypto.symbolic.PublicKeyS;


/*
 * Simple test for the supervisor code.
 */
public class SupervisorTest {
    public static void main(String[] args) {
        String[] candidates1 = {"Fred", "Wilma", "Barney" }; 
        SingleChoiceBallotDesign bd1 = new SingleChoiceBallotDesign().civitas$common$SingleChoiceBallotDesign$(LabelUtil.singleton().noComponents(), candidates1);
        
        String[] candidates2 = {"Homer", "Marje", "Barney" }; 
        ApprovalBallotDesign bd2 = new ApprovalBallotDesign().civitas$common$ApprovalBallotDesign$(LabelUtil.singleton().noComponents(), candidates2);
        
        String[] candidates3 = {"George", "Elroy", "Jane" }; 
        CondorcetBallotDesign bd3 = new CondorcetBallotDesign().civitas$common$CondorcetBallotDesign$(LabelUtil.singleton().noComponents(), candidates3);
        
//        String[] candidates4 = {"George", "Elroy", "Jane" }; 
//        String[] grades4 = {"Terrible", "Poor", "Mediocre", "Adequate" }; 
//        MajGradingBallotDesign bd4 = new MajGradingBallotDesign().civitas$common$MajGradingBallotDesign$(LabelUtil.singleton().noComponents(), candidates4, grades4);
        
        BallotDesign[] designs = {bd1, bd2, bd3};
        MultiBallotDesign bd = new MultiBallotDesign().civitas$common$MultiBallotDesign$(LabelUtil.singleton().noComponents(), designs);
        
        ElectionDetails ed = new ElectionDetails().civitas$common$ElectionDetails$(new ElectionID().civitas$common$ElectionID$("localhost", 7777, "1"), new PublicKeyS(8), new PublicKeyS(9), "name","description<>", "0.1", bd, "noon", "1pm", "2pm", CryptoUtil.factory().generateElGamalParameters(), 34, 128/8, 2);
        StringWriter sb = new StringWriter();
        ed.toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        String s = sb.toString();
        System.out.println("Message is " + s);
        String t = null;
        try {
            sb = new StringWriter();
            ElectionDetails.fromXML(LabelUtil.singleton().noComponents(), new StringReader(s)).toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
            t = sb.toString();
        }
        catch (IllegalArgumentException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } 
        System.out.println("Message is " + t);
        
//        TellerDetails td = new TellerDetails().civitas$common$TellerDetails$();
//        td.addRegistrationTeller(new Teller().civitas$common$Teller$("localhost", 7780));
//        td.addRegistrationTeller(new Teller().civitas$common$Teller$("localhost", 7781));
//        td.addTabulationTeller(new Teller().civitas$common$Teller$("localhost", 7782));
//
//        s = td.toXML();
//        System.out.println("Message is " + s);
//        t = null;
//        try {
//            t = TellerDetails.fromXML(new StringReader(s)).toXML();
//        }
//        catch (IllegalArgumentException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//        catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        } 
//        System.out.println("Message is " + t);
    }
 }
