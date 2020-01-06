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
import civitas.crypto.CryptoHashableList;
import civitas.crypto.ElGamalParameters;
import civitas.crypto.ElGamalProofDiscLogEquality;
import civitas.util.CivitasBigInteger;

/**
 * To prove that log v = log w, where v = g_1^x and w = g_2^x, let:
 *      z = random in Z_q
 *      a = g_1^z
 *      b = g_2^z
 *      c = hash(v,w,a,b)
 *      r = (z + cx) mod q
 * The proof is (a,b,c,r).
 * To verify, check that g_1^r = av^c (mod p) and g_2^r = bw^c (mod p).
 */
public class ElGamalProofDiscLogEqualityC implements ElGamalProofDiscLogEquality {

    public final ECPoint g1;
    public final ECPoint g2;

    public final ECPoint v;
    public final ECPoint w;

    public final ECPoint a;
    public final ECPoint b;
    public final BigInteger c;
    public final BigInteger r;

    public ElGamalProofDiscLogEqualityC(
            ECPoint g1,
            ECPoint g2,
            ECPoint a,
            ECPoint v,
            ECPoint w,
            ECPoint b,
            BigInteger c, BigInteger r) {
        this.g1 = g1;
        this.g2 = g2;
        this.v = v;
        this.w = w;
        this.a = a;
        this.b = b;
        this.c = c;
        this.r = r;
    }

    public static ElGamalProofDiscLogEqualityC constructProof(
        ElGamalParametersC params,
        ECPoint g1,
        ECPoint g2,
        BigInteger x)
    {

        CryptoFactoryC factory = CryptoFactoryC.singleton();

        ECPoint v = g1.multiply(x);
        ECPoint w = g2.multiply(x);

        BigInteger z = CryptoAlgs.randomElementDefault(params.params.getN());
        ECPoint a = g1.multiply(z);
        ECPoint b = g2.multiply(z);

        CryptoHashableList l = new CryptoHashableList();
        l.add(v);
        l.add(w);
        l.add(a);
        l.add(b);
        BigInteger c = factory.hashToDefaultBigInt(factory.hash(l)).mod(params.params.getN());

        BigInteger cx = CivitasBigInteger.modMultiply(c, x, params.params.getN());
        BigInteger r = CivitasBigInteger.modAdd(z, cx, params.params.getN());


        return new ElGamalProofDiscLogEqualityC(g1, g2, a, v, w, b, c, r);
    }

    public boolean verify(ElGamalParameters prms) {
        if (!(prms instanceof ElGamalParametersC)) return false;

        try {
            //To verify, check that g_1^r = av^c (mod p) and g_2^r = bw^c (mod p)
            return g1.multiply(r).equals(a.add(v.multiply(c))) &&
                   g2.multiply(r).equals(b.add(w.multiply(c)));
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
        s.print("<egPrfKnwDscLog>");

        s.print("<g1>");
        if (this.g1 != null) Util.escapeString(CryptoFactoryC.pointToString(this.g1), lbl, s);
        s.print("</g1>");
        s.print("<g2>");
        if (this.g2 != null) Util.escapeString(CryptoFactoryC.pointToString(this.g2), lbl, s);
        s.print("</g2>");
        s.print("<v>");
        if (this.v != null) Util.escapeString(CryptoFactoryC.pointToString(this.v), lbl, s);
        s.print("</v>");
        s.print("<w>");
        if (this.w != null) Util.escapeString(CryptoFactoryC.pointToString(this.w), lbl, s);
        s.print("</w>");
        s.print("<a>");
        if (this.a != null) Util.escapeString(CryptoFactoryC.pointToString(this.a), lbl, s);
        s.print("</a>");
        s.print("<b>");
        if (this.b != null) Util.escapeString(CryptoFactoryC.pointToString(this.b), lbl, s);
        s.print("</b>");
        s.print("<c>");
        if (this.c != null) Util.escapeString(CryptoFactoryC.defaultBigIntToString(this.c), lbl, s);
        s.print("</c>");
        s.print("<r>");
        if (this.r != null) Util.escapeString(CryptoFactoryC.defaultBigIntToString(this.r), lbl, s);
        s.print("</r>");

        s.print("</egPrfKnwDscLog>");
    }

    public static ElGamalProofDiscLogEquality fromXML(Label lbl, Reader r) throws IllegalArgumentException, IOException {
        Util.swallowTag(lbl, r, "egPrfKnwDscLog");
        String g1 = Util.unescapeString(Util.readSimpleTag(lbl, r, "g1"));
        String g2 = Util.unescapeString(Util.readSimpleTag(lbl, r, "g2"));
        String v = Util.unescapeString(Util.readSimpleTag(lbl, r, "v"));
        String w = Util.unescapeString(Util.readSimpleTag(lbl, r, "w"));
        String a = Util.unescapeString(Util.readSimpleTag(lbl, r, "a"));
        String b = Util.unescapeString(Util.readSimpleTag(lbl, r, "b"));
        String c = Util.unescapeString(Util.readSimpleTag(lbl, r, "c"));
        String rr = Util.unescapeString(Util.readSimpleTag(lbl, r, "r"));

        Util.swallowEndTag(lbl, r, "egPrfKnwDscLog");
        return new ElGamalProofDiscLogEqualityC(
            CryptoFactoryC.stringToPoint(g1),CryptoFactoryC.stringToPoint(g2),
            CryptoFactoryC.stringToPoint(a), CryptoFactoryC.stringToPoint(v),
            CryptoFactoryC.stringToPoint(w), CryptoFactoryC.stringToPoint(b),
            CryptoFactoryC.stringToDefaultBigInt(c), CryptoFactoryC.stringToDefaultBigInt(rr));
    }
}