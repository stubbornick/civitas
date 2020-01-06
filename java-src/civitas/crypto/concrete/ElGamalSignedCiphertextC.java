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
import civitas.crypto.ElGamalSignedCiphertext;

public class ElGamalSignedCiphertextC extends ElGamalCiphertextC implements ElGamalSignedCiphertext {
    public final BigInteger c;
    public final BigInteger d;

    public ElGamalSignedCiphertextC(ECPoint a, ECPoint b, BigInteger c, BigInteger d) {
        super(a,b);
        this.c = c;
        this.d = d;
    }

    public String toXML() {
        StringWriter sb = new StringWriter();
        toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        return sb.toString();
    }
    public void toXML(Label lbl, PrintWriter s) {
        s.print("<elGamalSignedCiphertext>");
        s.print("<a>");
        if (a != null) Util.escapeString(CryptoFactoryC.pointToString(this.a), lbl, s);
        s.print("</a>");
        s.print("<b>");
        if (b != null) Util.escapeString(CryptoFactoryC.pointToString(this.b), lbl, s);
        s.print("</b>");
        s.print("<c>");
        if (c != null) Util.escapeString(CryptoFactoryC.defaultBigIntToString(this.c), lbl, s);
        s.print("</c>");
        s.print("<d>");
        if (d != null) Util.escapeString(CryptoFactoryC.defaultBigIntToString(this.d), lbl, s);
        s.print("</d>");
        s.print("</elGamalSignedCiphertext>");
    }

    public static ElGamalSignedCiphertext fromXMLsub(Label lbl, Reader r) throws IllegalArgumentException, IOException {
        Util.swallowTag(lbl, r, "elGamalSignedCiphertext");
        ECPoint a = null;
        String sa = Util.readSimpleTag(lbl, r, "a");
        if (sa != null && sa.length() > 0) {
            a = CryptoFactoryC.stringToPoint(Util.unescapeString(sa));
        }

        ECPoint b = null;
        String sb = Util.readSimpleTag(lbl, r, "b");
        if (sb != null && sb.length() > 0) {
            b = CryptoFactoryC.stringToPoint(Util.unescapeString(sb));
        }

        BigInteger c = null;
        String sc = Util.readSimpleTag(lbl, r, "c");
        if (sc != null && sc.length() > 0) {
            c = CryptoFactoryC.stringToDefaultBigInt(Util.unescapeString(sc));
        }

        BigInteger d = null;
        String sd = Util.readSimpleTag(lbl, r, "d");
        if (sd != null && sd.length() > 0) {
            d = CryptoFactoryC.stringToDefaultBigInt(Util.unescapeString(sd));
        }

        Util.swallowEndTag(lbl, r, "elGamalSignedCiphertext");
        return new ElGamalSignedCiphertextC(a, b, c, d);
    }
    public void toUnsignedCiphertextXML(Label lbl, PrintWriter sb) {
        super.toXML(lbl, sb);
    }

}
