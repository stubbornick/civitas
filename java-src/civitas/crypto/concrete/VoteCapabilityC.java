/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */
package civitas.crypto.concrete;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Reader;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import jif.lang.IDComparable;
import jif.lang.Label;
import until.lang.LabelUntilUtil;
import civitas.common.Util;
import civitas.crypto.CryptoException;
import civitas.crypto.VoteCapability;

public class VoteCapabilityC extends ElGamalMsgC implements VoteCapability {


    public VoteCapabilityC(BigInteger c, ElGamalParametersC params) throws CryptoException {
        super(c, params);
    }

    public VoteCapabilityC(String c, ElGamalParametersC params) throws CryptoException {
        super(c, params);
    }

    public VoteCapabilityC(ECPoint c) {
		super(c);
	}

	public boolean equals(IDComparable other) {
        return equals(LabelUntilUtil.singleton().noComponents(), other);
    }

    public boolean equals(Label lbl, IDComparable obj) {
        if (obj instanceof VoteCapabilityC) {
            VoteCapabilityC that = (VoteCapabilityC)obj;
            return super.equals(that);
        }
        return false;
    }

    public void toXML(Label lbl, PrintWriter s) {
        s.print('<'); s.print(OPENING_TAG); s.print('>');
        if (this.m != null) {
            Util.escapeString(CryptoFactoryC.pointToString(this.m), null, s);
        }
        s.print("</"); s.print(OPENING_TAG); s.print('>');
    }
    public static VoteCapability fromXML(Label lbl, Reader r) throws IllegalArgumentException, IOException {
        String s = Util.unescapeString(Util.readSimpleTag(lbl, r, OPENING_TAG));
        return new VoteCapabilityC(CryptoFactoryC.stringToPoint(s));
    }

}
