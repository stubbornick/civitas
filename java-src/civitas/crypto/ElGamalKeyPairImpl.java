/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */
package civitas.crypto;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import civitas.crypto.concrete.ElGamalPrivateKeyC;
import civitas.crypto.concrete.ElGamalPublicKeyC;

public class ElGamalKeyPairImpl implements ElGamalKeyPair {
	final ElGamalPublicKey K;
	final ElGamalPrivateKey k;

	public ElGamalKeyPairImpl(ECPublicKeyParameters K, ECPrivateKeyParameters k, ElGamalParameters params) {
		this.K = new ElGamalPublicKeyC(K.getQ(), params);
		this.k = new ElGamalPrivateKeyC(k.getD(), params);
	}

	public ElGamalPublicKey publicKey() {
		return K;
	}

	public ElGamalPrivateKey privateKey() {
		return k;
	}
}