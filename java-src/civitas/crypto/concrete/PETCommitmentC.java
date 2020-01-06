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
import civitas.crypto.PETCommitment;

public class PETCommitmentC implements PETCommitment {
    public final BigInteger hash;

    public PETCommitmentC(BigInteger hash) {
        this.hash = hash;
    }
    public String toXML() {
        StringWriter sb = new StringWriter();
        toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        return sb.toString();
    }
    public void toXML(Label lbl, PrintWriter s) {
        s.print('<'); s.print(OPENING_TAG); s.print('>');

        if (hash != null) Util.escapeString(CryptoFactoryC.defaultBigIntToString(this.hash), lbl, s);

        s.print("</"); s.print(OPENING_TAG); s.print('>');
    }

    public static PETCommitmentC fromXML(Label lbl, Reader r) throws IllegalArgumentException, IOException {
        String d = Util.unescapeString(Util.readSimpleTag(lbl, r, OPENING_TAG));
        return new PETCommitmentC(CryptoFactoryC.stringToDefaultBigInt(d));
    }

}