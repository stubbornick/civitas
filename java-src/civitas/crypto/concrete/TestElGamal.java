/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */
package civitas.crypto.concrete;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import civitas.crypto.*;

import jif.lang.LabelUtil;

public class TestElGamal {
	public static final CryptoFactoryC f = CryptoFactoryC.singleton();
	public static ElGamalParametersC ps = null;

	public static ElGamalMsgC message;
	public static final String attack = "Attack at dawn";

	private static ElGamalParametersC ps() {
		if (ps == null) {
			ps = (ElGamalParametersC) f.generateElGamalParameters();
		}
		return ps;
    }

	public static void test(final String s, final boolean b) {
		System.out.println(s + " ? " + (b ? "ok" : "oops !!!!!!!!!!!!!!!!!!!!!!!!!!!!"));
	}


	public static void main(final String[] args) throws CryptoException {
		System.out.println("= ps =");
		ps();
		System.out.println("= msgTest =");
		msgTest();
		System.out.println("= encTest =");
		encTest();
		System.out.println("= qrTest =");
		qrTest();
		System.out.println("= egHomoTestOriginal =");
		egHomoTestOriginal();
		System.out.println("= egHomoTest =");
		egHomoTest();
	}


	public static void msgTest() {
		try {
			TestElGamal.message = new ElGamalMsgC(attack, ps);
		} catch (final CryptoException e) {
			System.out.println("oops");
		}
		boolean caught = false;
		try {
			new ElGamalMsgC(ps.params.getN().add(BigInteger.ONE), ps);
		} catch (final CryptoException e) {
			System.out.println("Reject q+1 as message ? ok");
			caught = true;
		}
		if (!caught) {
			System.out.println("Reject q+1 as message ? oops");
		}
	}

	public static void encTest() {
		final ElGamalMsgC m = TestElGamal.message;

		final ElGamalKeyPair p = f.generateElGamalKeyPair(ps);
		final ElGamalPublicKey K = p.publicKey();
		final ElGamalPrivateKey k = p.privateKey();
		final ElGamalCiphertext c = f.elGamalEncrypt(K, m);
		final ElGamalKeyPair p2 = f.generateElGamalKeyPair(ps);
		final ElGamalPrivateKey k2 = p2.privateKey();

		try {
			final ElGamalMsgC m1 = (ElGamalMsgC) f.elGamalDecrypt(k,c);
			test("Encryption correct", m.equals(m1));

			final ElGamalMsgC m2 = (ElGamalMsgC) f.elGamalDecrypt(k2,c);
			test("Decryption under wrong key", !m.equals(m2));

			final ElGamalCiphertext c2 = f.elGamalReencrypt(K, c);
			test("Reencryption changes ciphertext", !c.equals(c2));

			final ElGamalMsgC m3 = (ElGamalMsgC) f.elGamalDecrypt(k,c2);
			test("Reencryption preserves message", m.equals(m3));

			final ElGamalSignedCiphertextC c3 = (ElGamalSignedCiphertextC)f.elGamalSignedEncrypt(K, m);
			final ElGamalMsgC m4 = (ElGamalMsgC)f.elGamalDecrypt(k,c3);
			test("Signed encryption correct", m.equals(m4));

			final boolean b = f.elGamalVerify(ps, c3);
			test("Scnorr signature checks", b);

			final ElGamalSignedCiphertext c4 = new ElGamalSignedCiphertextC(c3.a, c3.b, BigInteger.ONE, BigInteger.ONE);
			final boolean b2 = f.elGamalVerify(ps, c4);
			test("Corrupted signature detected", !b2);

		} catch (final CryptoException e) {
			System.out.println("oops: " + e);
		}
	}

	public static void qrTest() {
		System.out.println("= qrTest =");

		final ElGamalParametersC ps2 = (ElGamalParametersC) f.generateElGamalParameters();
		try {
			final ElGamalMsgC m2 = (ElGamalMsgC) f.elGamalMsg("Attack at dawn", ps2);
			test("Decode QR", m2.plaintextStringValue(ps2).equals(attack));
		} catch (final CryptoException ce) {
			System.out.println("oops: " + ce);
		}
	}

	/**
     * test homomorphic properties of el gamal
     */
	private static void egHomoTestOriginal() {
        final ElGamalKeyPair pair = f.generateElGamalKeyPair(ps);
        final ElGamalPrivateKeyC k = (ElGamalPrivateKeyC)pair.privateKey();
        final ElGamalPublicKeyC K = (ElGamalPublicKeyC)pair.publicKey();

        final VoteCapabilityShareC m1 = (VoteCapabilityShareC)f.generateVoteCapabilityShare(ps);
        final VoteCapabilityShareC m2 = (VoteCapabilityShareC)f.generateVoteCapabilityShare(ps);
        final VoteCapabilityShare[][] vs = new VoteCapabilityShare[2][1];
        vs[0][0] = m1;
        vs[1][0] = m2;

        final ElGamalReencryptFactorC r = new ElGamalReencryptFactorC(BigInteger.ONE);

        final ElGamalSignedCiphertextC c1 = (ElGamalSignedCiphertextC)f.elGamalSignedEncrypt(K, m1, r);
        final ElGamalSignedCiphertextC c2 = (ElGamalSignedCiphertextC)f.elGamalSignedEncrypt(K, m2, r);
		// System.err.println("c1 = " + c1.a + "," + c1.b);
		// System.err.println("c2 = " + c2.a + "," + c2.b);
        final ElGamalSignedCiphertext[][] cs = new ElGamalSignedCiphertext[2][1];
        cs[0][0] = c1;
        cs[1][0] = c2;

        final ElGamalMsg mf = f.combineVoteCapabilityShares(LabelUtil.singleton().noComponents(), vs, ps)[0];
        final ElGamalCiphertextC cf = (ElGamalCiphertextC)f.multiplyCiphertexts(LabelUtil.singleton().noComponents(), cs, ps)[0];

        ElGamalMsg md = null;
        try {
            md = f.elGamalDecrypt(k, cf);
        }
        catch (final CryptoException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
       	// System.err.println("md = dec(cf) = " + md.intValue());
        test("eg homomorphic", md.equals(mf));
	}

	/**
	 * test homomorphic properties of el gamal
	 *
	 * @throws CryptoException
	 */
	private static void egHomoTest() throws CryptoException {
        final ElGamalKeyPair pair = f.generateElGamalKeyPair(ps);
        final ElGamalPrivateKeyC k = (ElGamalPrivateKeyC)pair.privateKey();
		final ElGamalPublicKeyC K = (ElGamalPublicKeyC)pair.publicKey();

		ECPoint pt1 = ps.encodePlaintext(BigInteger.valueOf(10));
		ECPoint pt2 = ps.encodePlaintext(BigInteger.valueOf(24));

		ElGamalMsgC m1 = new ElGamalMsgC(pt1);
		ElGamalMsgC m2 = new ElGamalMsgC(pt2);
		ElGamalMsgC mMult = new ElGamalMsgC(pt1.add(pt2));

		// System.err.println("m1 = " + m1);
		// System.err.println("m2 = " + m2);
		// System.err.println("mMult = " + mMult);

        final ElGamalSignedCiphertextC c1 = (ElGamalSignedCiphertextC)f.elGamalSignedEncrypt(K, m1);
        final ElGamalSignedCiphertextC c2 = (ElGamalSignedCiphertextC)f.elGamalSignedEncrypt(K, m2);
		// System.err.println("c1 = " + c1.a + "," + c1.b);
		// System.err.println("c2 = " + c2.a + "," + c2.b);

		final ElGamalSignedCiphertext[][] cs = new ElGamalSignedCiphertext[2][1];
        cs[0][0] = c1;
        cs[1][0] = c2;

		final ElGamalCiphertextC cMult = (ElGamalCiphertextC)f.multiplyCiphertexts(LabelUtil.singleton().noComponents(), cs, ps)[0];
		// System.err.println("cMult = " + cMult.a + "," + cMult.b);

        ElGamalMsg mRes = null;
        try {
            mRes = f.elGamalDecrypt(k, cMult);
        }
        catch (final CryptoException e) {
            e.printStackTrace();
        }
       	// System.err.println("mRes = dec(cMult) = " + mRes);
        test("eg homomorphic", mRes.equals(mMult));
    }
}
