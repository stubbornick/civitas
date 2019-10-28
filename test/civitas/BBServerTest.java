/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */ 
package civitas;

import java.io.*;

import jif.lang.LabelUtil;
import civitas.bboard.client.BBClientUtil;
import civitas.common.ElectionID;
import civitas.crypto.CryptoUtil;
import civitas.crypto.PrivateKey;
import civitas.crypto.PublicKey;

/**
 * Simple test of a bulletin board server.
 */
public class BBServerTest {
    public static void main(String[] args) throws IllegalArgumentException, FileNotFoundException, IOException {
        BBClientUtil bbcu = new BBClientUtil().civitas$bboard$client$BBClientUtil$("localhost", 3444);
        PublicKey pubKey = CryptoUtil.factory().publicKeyFromFile("testData/bbPublicKey.xml");
        PrivateKey privKey = CryptoUtil.factory().privateKeyFromFile("testData/bbPrivateKey.xml");
        System.err.println("Create board");
        String bbid = "3";//bbcu.newBoard(pubKey);
        bbcu = new BBClientUtil().civitas$bboard$client$BBClientUtil$("localhost",3444, bbid);
        
        ElectionID id = new ElectionID().civitas$common$ElectionID$("localhost", 3444, bbid);
        StringWriter sb = new StringWriter();
        id.toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        System.err.println(sb.toString());
        
        // post a message
        System.err.println("post");
        String stamp = bbcu.post("test", id, privKey);
        System.err.println("  stamp was " + stamp);

        // retrieve the hash
        System.err.println("hash");
        String hash = CryptoUtil.factory().bytesToBase64(LabelUtil.singleton().noComponents(), bbcu.retrieveHash(pubKey, "test", null, null));
        System.err.println("  hash was " + hash);
        
/*        if (args.length < 2 || args.length > 3) {
            System.err.println("usage: bbservertest host port [bbid]");
            System.exit(1);
        }
        String host = args[0];
        int port = 0;
        port = Integer.parseInt(args[1]);
        System.out.println("Trying BBServer: " + host + ":"+port);
        Principal bbPrincipal = CryptoUtil.factory().keyPair("BB", CryptoUtil.factory().publicKeyFromFile("file"));
        BBClientUtil cu = new BBClientUtil(bbPrincipal).civitas$bboard$client$BBClientUtil$();
        
        String bbid = null;
        if (args.length > 2) {
            bbid = args[2];
        }
        
        try {
            if (bbid == null) {
                System.out.println("Creating new board");
                bbid = cu.newBoard(host, port);
            }
            System.out.println("bbid is " + bbid);
            List l = cu.retrieve(host, port, bbid);
            System.out.println("Got list " + l.toString());
            String stamp = cu.post(host, port, bbid, "mouth", "Long message. Long message. Long message. Long message. Long message. Long message. Long message. Long message. Long message. Long message. Long message. Long message. Long message. Long message. Long message. Long message. ");
//            String stamp = cu.post(host, port, bbid, "mouth", "Short");
            System.out.println("Posted message, with stamp " + stamp);
            l = cu.retrieve(host, port, bbid);
            System.out.println("list is now " + l.toString());

            l = cu.retrieveParams(host, port, bbid, "u", null, null);
            System.out.println("list with param is now " + l.toString());
        
        }
        catch (NumberFormatException e) {
            e.printStackTrace();
        }
        catch (IOException e) {   
            e.printStackTrace();
        }
        */
    }
 }
