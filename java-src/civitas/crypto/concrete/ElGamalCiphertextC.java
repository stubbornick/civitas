/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */
package civitas.crypto.concrete;

import java.io.*;

import org.bouncycastle.math.ec.ECPoint;

import jif.lang.Label;
import jif.lang.LabelUtil;
import civitas.common.Util;
import civitas.crypto.ElGamalCiphertext;

public class ElGamalCiphertextC implements ElGamalCiphertext {
    public final ECPoint a;
    public final ECPoint b;

    public ElGamalCiphertextC(ECPoint a, ECPoint b) {
        this.a = a;
        this.b = b;
    }

    public String toXML() {
        StringWriter sb = new StringWriter();
        toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        return sb.toString();
    }
    public void toXML(Label lbl, PrintWriter s) {
        s.print('<');
        s.print(OPENING_TAG);
        s.print('>');
        s.print("<a>");
        if (a != null) Util.escapeString(CryptoFactoryC.pointToString(this.a), lbl, s);
        s.print("</a>");
        s.print("<b>");
        if (b != null) Util.escapeString(CryptoFactoryC.pointToString(this.b), lbl, s);
        s.print("</b>");
        s.print("</");
        s.print(OPENING_TAG);
        s.print('>');
    }

    public static ElGamalCiphertextC fromXML(Label lbl, Reader r) throws IllegalArgumentException, IOException {
        Util.swallowTag(lbl, r, OPENING_TAG);
        ECPoint a = null;
        String sa = Util.unescapeString(Util.readSimpleTag(lbl, r, "a"));
        if (sa != null && sa.length() > 0) {
            a = CryptoFactoryC.stringToPoint(sa);
        }

        ECPoint b = null;
        String sb = Util.unescapeString(Util.readSimpleTag(lbl, r, "b"));
        if (sb != null && sb.length() > 0) {
            b = CryptoFactoryC.stringToPoint(sb);
        }

        Util.swallowEndTag(lbl, r, OPENING_TAG);
        return new ElGamalCiphertextC(a, b);
    }

    public void toUnsignedCiphertextXML(Label lbl, PrintWriter s) {
        toXML(lbl, s);
    }

    public boolean equals(Object o) {
        if (!(o instanceof ElGamalCiphertextC)) {
            return false;
        }

        ElGamalCiphertextC x = (ElGamalCiphertextC) o;
        return a.equals(x.a) && b.equals(x.b);
    }

    public boolean equals(ElGamalCiphertext c) {
        return equals((Object)c);
    }

    public int hashCode() {
        return a.hashCode() ^ b.hashCode();
    }
}
