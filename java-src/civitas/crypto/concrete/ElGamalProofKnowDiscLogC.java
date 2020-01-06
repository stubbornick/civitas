/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */
package civitas.crypto.concrete;

import java.io.*;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import jif.lang.Label;
import jif.lang.LabelUtil;
import civitas.common.Util;
import civitas.crypto.ElGamalParameters;
import civitas.crypto.ElGamalProofKnowDiscLog;

/**
 * Proof that an entity knows x in v = g^x.
 */
public class ElGamalProofKnowDiscLogC implements ElGamalProofKnowDiscLog {

    /* p,q,g are the parameters of the ElGamal (not included here).
     * z = random in Z_q
     * a = g^z mod p
     * c = hash(v,a)
     * r = (z + cx) mod q
     *
     * To verify proof, check that g^r = av^c (mod p)
     */
    public final ECPoint a;
    public final BigInteger c;
    public final BigInteger r;
    public final ECPoint v;

    public ElGamalProofKnowDiscLogC(ECPoint a, BigInteger c, BigInteger r, ECPoint v) {
        this.a = a;
        this.c = c;
        this.r = r;
        this.v = v;
    }

    public boolean verify(ElGamalParameters prms) {
        if (!(prms instanceof ElGamalParametersC)) return false;
        ElGamalParametersC params = (ElGamalParametersC)prms;
        try {
            ECPoint u = params.params.getG().multiply(r);
            ECPoint w = a.add(v.multiply(c));

            return u.equals(w);
        }
        catch (NullPointerException e) {
            return false;
        }
        catch (ArithmeticException e) {
            return false;
        }
    }
    public String toXML() {
        StringWriter sb = new StringWriter();
        toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        return sb.toString();
    }
    public void toXML(Label lbl, PrintWriter s) {
        s.print("<elGamalProofKnowDiscLog>");

        s.print("<a>");
        if (this.a != null) Util.escapeString(CryptoFactoryC.pointToString(this.a), lbl, s);
        s.print("</a>");
        s.print("<c>");
        if (this.c != null) Util.escapeString(CryptoFactoryC.defaultBigIntToString(this.c), lbl, s);
        s.print("</c>");
        s.print("<r>");
        if (this.r != null) Util.escapeString(CryptoFactoryC.defaultBigIntToString(this.r), lbl, s);
        s.print("</r>");
        s.print("<v>");
        if (this.v != null) Util.escapeString(CryptoFactoryC.pointToString(this.v), lbl, s);
        s.print("</v>");

        s.print("</elGamalProofKnowDiscLog>");
    }

    public static ElGamalProofKnowDiscLogC fromXML(Label lbl, Reader r) throws IllegalArgumentException, IOException {
        Util.swallowTag(lbl, r, "elGamalProofKnowDiscLog");
        String a = Util.unescapeString(Util.readSimpleTag(lbl, r, "a"));
        String c = Util.unescapeString(Util.readSimpleTag(lbl, r, "c"));
        String rr = Util.unescapeString(Util.readSimpleTag(lbl, r, "r"));
        String v = Util.unescapeString(Util.readSimpleTag(lbl, r, "v"));

        Util.swallowEndTag(lbl, r, "elGamalProofKnowDiscLog");
        return new ElGamalProofKnowDiscLogC(
            CryptoFactoryC.stringToPoint(a),
            CryptoFactoryC.stringToDefaultBigInt(c),
            CryptoFactoryC.stringToDefaultBigInt(rr),
            CryptoFactoryC.stringToPoint(v)
            );
    }
}