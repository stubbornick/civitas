/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */
package civitas.crypto.concrete;

import java.io.*;
import java.math.BigInteger;

import jif.lang.Label;
import jif.lang.LabelUtil;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import civitas.common.Util;
import civitas.crypto.CryptoError;
import civitas.crypto.CryptoException;
import civitas.crypto.ElGamalParameters;

/**
 * The ElGamal cryptosystem defined by these parameters is over
 * the unique order q subgroup of Z*p, where p = 2kq + 1, and
 * p and q are prime
 */
class ElGamalParametersC implements ElGamalParameters {

	public static final String EC_NAMED_CURVE = "secp256k1";

	/**
	 * Bouncy Castle elliptic curve parameters.
	 */
	protected final ECDomainParameters params;

	public ElGamalParametersC(ECDomainParameters params) {
		this.params = params;
	}

	public String toXML() {
		StringWriter sb = new StringWriter();
		toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
		return sb.toString();
	}
	public void toXML(Label lbl, PrintWriter s) {
		s.print("<elGamalParameters>");

		s.print("<ECNamedCurve>");
		s.print(EC_NAMED_CURVE);
		s.print("</ECNamedCurve>");

		s.print("</elGamalParameters>");
	}

	public static ElGamalParametersC getDefaultParams() {
		ECParameterSpec namedCurve = ECNamedCurveTable.getParameterSpec(EC_NAMED_CURVE);

		ECDomainParameters params = new ECDomainParameters(
			namedCurve.getCurve(),
			namedCurve.getG(),
			namedCurve.getN()
			);

		return new ElGamalParametersC(params);
	}

	public static ElGamalParametersC fromXML(Label lbl, Reader r) throws IllegalArgumentException, IOException {
		Util.swallowTag(lbl, r, "elGamalParameters");
		String curveName = Util.unescapeString(Util.readSimpleTag(lbl, r, "p"));
		Util.swallowEndTag(lbl, r, "elGamalParameters");

		if (curveName != ElGamalParametersC.EC_NAMED_CURVE) {
			throw new CryptoError("Only secp256k1 curve is supported");
		}
		return ElGamalParametersC.getDefaultParams();
	}

	public boolean equals(Object o) {
		if (!(o instanceof ElGamalParametersC)) {
			return false;
		}

		ElGamalParametersC x = (ElGamalParametersC) o;

		return this.params.equals(x.params);
	}

	public int hashCode() {
		return this.params.hashCode();
	}

	public BigInteger decodeMessage(ECPoint m) throws CryptoException {
		throw new CryptoException("Decoding is not supported for ECElGamal.");
	}

	public ECPoint encodePlaintext(BigInteger p) throws CryptoException {
		ECMultiplier mult = new FixedPointCombMultiplier();
		return mult.multiply(params.getG(), p);
	}

	/**
	 * Attempt to decode a message by brute force.
	 * @return If m does not decode to an integer i such that 1 <= i <= L.
	 */
	public int bruteForceDecode(ECPoint m, int L) throws CryptoException {
		// first, try doing this the nice way
		try {
			BigInteger c = decodeMessage(m);
			int i = c.intValue();
			if (1 <= i && i <= L) {
				return i;
			}
		} catch (CryptoException c) {
			// ignore and attempt brute force
		}

		// now try brute force
		ECPoint g = params.getG();
		ECPoint x = g;
		for (int i = 1; i <= L; i++) {
			if (x.equals(m)) {
				return i;
			}
			x = x.add(g);
		}

		throw new CryptoException("Brute force decoding failed");
	}
}
