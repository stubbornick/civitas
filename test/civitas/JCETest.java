/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */ 
package civitas;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Simple test for the Java Crypto Extension.
 */
public class JCETest {
    public static void main(String[] args) {
        System.out.print("Adding BouncyCastle provider... ");
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("done.");
        String alg = "ElGamal";
         
        // try an ElGamal encryption
        try {
            System.out.print("Creating ElGamal key-pair generator... ");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
            System.out.println("done.");
            
            DHParameterSpec elParams = new DHParameterSpec(p, g);
            kpg.initialize(elParams);
            //kpg.initialize(128);
            System.out.println("Generating ElGamal key-pair... ");
            KeyPair kp = kpg.generateKeyPair();
            
            Cipher cipherEnc = Cipher.getInstance(alg, "BC");

            System.out.println("Encrypting...");
            String msg = "Attack at dawn.";
            cipherEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            System.out.println("block size is " + cipherEnc.getBlockSize());
            byte[] encrypted = cipherEnc.doFinal(msg.getBytes());
            
            System.out.println("Decrypting...");
            Cipher cipherDec = Cipher.getInstance(alg, "BC");
            cipherDec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            byte[] decrypted = cipherDec.doFinal(encrypted);
            
            // convert the bytes to a string.
            System.out.println("Decrypted message is " + new String(decrypted));
            
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
    static BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    static BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
 }
