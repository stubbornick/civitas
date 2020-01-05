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
import civitas.common.Util;
import civitas.crypto.ElGamalAbstractKey;
import civitas.crypto.ElGamalParameters;
import civitas.crypto.ElGamalPrivateKey;

public class ElGamalPrivateKeyC extends ElGamalAbstractKey implements ElGamalPrivateKey {

    public final BigInteger x;

    public ElGamalPrivateKeyC(BigInteger x, ElGamalParameters params) {
        super(params);
        this.x = x;
    }

    public String toXML() {
        StringWriter sb = new StringWriter();
        toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        return sb.toString();
    }
    public void toXML(Label lbl, PrintWriter s) {
        s.print("<elGamalPrivateKey>");

        s.print("<params>");
        if (this.params != null) {
            this.params.toXML(lbl, s);
        }
        s.print("</params>");
        s.print("<x>");
        if (this.x != null) Util.escapeString(CryptoFactoryC.defaultBigIntToString(x), lbl, s);
        s.print("</x>");

        s.print("</elGamalPrivateKey>");
    }

    public static ElGamalPrivateKeyC fromXML(Label lbl, Reader r) throws IllegalArgumentException, IOException {
        Util.swallowTag(lbl, r, "elGamalPrivateKey");
        Util.swallowTag(lbl, r, "params");
        ElGamalParameters params = ElGamalParametersC.fromXML(lbl, r);
        Util.swallowEndTag(lbl, r, "params");
        String x = Util.unescapeString(Util.readSimpleTag(lbl, r, "x"));
        Util.swallowEndTag(lbl, r, "elGamalPrivateKey");
        return new ElGamalPrivateKeyC(CryptoFactoryC.stringToDefaultBigInt(x), params);
    }
}
