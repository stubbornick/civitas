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
import civitas.crypto.CryptoError;
import civitas.crypto.CryptoHashableList;
import civitas.crypto.ElGamalCiphertext;
import civitas.crypto.ElGamalProofDVR;
import civitas.crypto.ElGamalPublicKey;
import civitas.util.CivitasBigInteger;

public class ElGamalProofDVRC implements ElGamalProofDVR {
    private final ElGamalCiphertextC e;
    private final ElGamalCiphertextC eprime;
    public final BigInteger c;
    public final BigInteger w;
    public final BigInteger r;
    public final BigInteger u;

    public ElGamalProofDVRC(ElGamalCiphertextC e, ElGamalCiphertextC eprime,
            BigInteger c, BigInteger w, BigInteger r, BigInteger u) {
        this.e = e;
        this.eprime = eprime;
        this.c = c;
        this.w = w;
        this.r = r;
        this.u = u;
    }

    public static ElGamalProofDVRC constructProof(ElGamalCiphertextC e, ElGamalCiphertextC eprime,
            ElGamalPublicKeyC key, ElGamalPublicKeyC verifierKey,
            BigInteger zeta) {
        CryptoFactoryC factory = CryptoFactoryC.singleton();

        // check that the inputs are correct
        // if (!factory.elGamalReencrypt(key, e, new ElGamalReencryptFactorC(zeta)).equals(eprime)) {
        //     throw new CryptoError("Incorrect value for zeta passed in");
        // }

        ElGamalParametersC ps = (ElGamalParametersC)key.getParams();
        BigInteger N = ps.params.getN();
        ECPoint G = ps.params.getG();

        BigInteger d = CryptoAlgs.randomElementDefault(N);
        BigInteger w = CryptoAlgs.randomElementDefault(N);
        BigInteger r = CryptoAlgs.randomElementDefault(N);
        ECPoint h = key.y;
        ECPoint hv = verifierKey.y;
        ECPoint a = G.multiply(d);
        ECPoint b = h.multiply(d);
        ECPoint s = G.multiply(w).add(hv.multiply(r));
        CryptoHashableList l = new CryptoHashableList();
        l.add(e.a);
        l.add(e.b);
        l.add(eprime.a);
        l.add(eprime.b);
        l.add(a);
        l.add(b);
        l.add(s);
        BigInteger c = factory.hashToDefaultBigInt(factory.hash(l)).mod(N);

        BigInteger u = CivitasBigInteger.modAdd(
            d,
            CivitasBigInteger.modMultiply(
                zeta,
                CivitasBigInteger.modAdd(c, w, N),
                N
                ),
            N
            );

        return new ElGamalProofDVRC(e, eprime, c, w, r, u);

    }

    public static ElGamalProofDVRC fakeProof(
        ElGamalCiphertextC e,
        ElGamalCiphertextC et,
        ElGamalPublicKeyC key,
        ElGamalPublicKeyC verifierKey,
        ElGamalPrivateKeyC verifierPrivKey)
    {
        CryptoFactoryC factory = CryptoFactoryC.singleton();

        ElGamalParametersC ps = (ElGamalParametersC)key.getParams();
        BigInteger N = ps.params.getN();
        ECPoint G = ps.params.getG();
        //BigInteger hv = verifierKey.y;
        BigInteger zv = verifierPrivKey.x;

        ECPoint h = key.y;
        ECPoint x = e.a;
        ECPoint y = e.b;
        ECPoint xt = et.a;
        ECPoint yt = et.b;

        /*
         *  A verifier can simulate a "proof" that any e~=(x~,y~) is a reencryption of e.
         * Select \alpha, \beta, u~ at random from Z_q
         * Compute:
         *     o a~ (g^u~) / ((x~/x)^(\alpha))
         *     o b~ = (h^u~) / ((y~/y)^(\alpha))
         *     o s~ = g^(\beta)
         *     o E~ = e||e~
         *     o c~ = hash(E~||a~||b~||s~)
         *     o w~ = \alpha - c~ (mod q)
         *     o r~ = (\beta - w~)/(z_v) (mod q)
         * (c~, w~, r~, u~) will verify as a proof for E~.
         */
        BigInteger alpha = CryptoAlgs.randomElementDefault(N);
        BigInteger beta = CryptoAlgs.randomElementDefault(N);
        BigInteger ut = CryptoAlgs.randomElementDefault(N);

        ECPoint at = G.multiply(ut).subtract(xt.subtract(x).multiply(alpha));
        ECPoint bt = h.multiply(ut).subtract(yt.subtract(y).multiply(alpha));
        ECPoint st = G.multiply(beta);

        CryptoHashableList l = new CryptoHashableList();
        l.add(e.a);
        l.add(e.b);
        l.add(et.a);
        l.add(et.b);
        l.add(at);
        l.add(bt);
        l.add(st);
        BigInteger ct = factory.hashToDefaultBigInt(factory.hash(l)).mod(N);

        BigInteger wt = CivitasBigInteger.modSubtract(alpha, ct, N);
        BigInteger rt = CivitasBigInteger.modDivide(CivitasBigInteger.modSubtract(beta, wt, N), zv, N);

        return new ElGamalProofDVRC(e, et, ct, wt, rt, ut);
    }

    public boolean verify(ElGamalPublicKey K, ElGamalPublicKey verifierKey) {
        CryptoFactoryC factory = CryptoFactoryC.singleton();

        ElGamalParametersC ps = (ElGamalParametersC)K.getParams();
        BigInteger N = ps.params.getN();
        ECPoint G = ps.params.getG();
        ElGamalPublicKeyC key = (ElGamalPublicKeyC)K;

        ECPoint hv = ((ElGamalPublicKeyC)verifierKey).y;
        ECPoint h = key.y;
        ECPoint x = e.a;
        ECPoint y = e.b;
        ECPoint xp = eprime.a;
        ECPoint yp = eprime.b;

        /*
         * a' = (g^u) / ((x'/x)^(c+w))
         * b' = (h^u) / ((y'/y)^(c+w))
         * s' = (g^w)*((h_v)^r)
         * c' = hash(E||a'||b'||s')
         */

        ECPoint ap = G.multiply(u).subtract(xp.subtract(x).multiply(CivitasBigInteger.modAdd(c, w, N)));
        ECPoint bp = h.multiply(u).subtract(yp.subtract(y).multiply(CivitasBigInteger.modAdd(c, w, N)));
        ECPoint sp = G.multiply(w).add(hv.multiply(r));

        CryptoHashableList l = new CryptoHashableList();
        l.add(e.a);
        l.add(e.b);
        l.add(eprime.a);
        l.add(eprime.b);
        l.add(ap);
        l.add(bp);
        l.add(sp);
        BigInteger cp = factory.hashToDefaultBigInt(factory.hash(l)).mod(N);

        return cp.equals(c);
    }

    public ElGamalCiphertext getE() {
        return e;
    }

    public ElGamalCiphertext getEprime() {
        return eprime;
    }

    public String toXML() {
        StringWriter sb = new StringWriter();
        toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        return sb.toString();
    }
    public void toXML(Label lbl, PrintWriter s) {
        s.print("<elGamalProofDVR>");
        e.toXML(lbl, s);
        eprime.toXML(lbl, s);
        s.print("<c>");
        Util.escapeString(CryptoFactoryC.defaultBigIntToString(c), lbl, s);
        s.print("</c>");
        s.print("<w>");
        Util.escapeString(CryptoFactoryC.defaultBigIntToString(w), lbl, s);
        s.print("</w>");
        s.print("<r>");
        Util.escapeString(CryptoFactoryC.defaultBigIntToString(r), lbl, s);
        s.print("</r>");
        s.print("<u>");
        Util.escapeString(CryptoFactoryC.defaultBigIntToString(u), lbl, s);
        s.print("</u>");
        s.print("</elGamalProofDVR>");
    }

    public static ElGamalProofDVR fromXML(Label lbl, Reader reader) throws IllegalArgumentException, IOException {
        Util.swallowTag(lbl, reader, "elGamalProofDVR");
        ElGamalCiphertextC e = (ElGamalCiphertextC)CryptoFactoryC.singleton().elGamalCiphertextFromXML(lbl, reader);
        ElGamalCiphertextC eprime = (ElGamalCiphertextC)CryptoFactoryC.singleton().elGamalCiphertextFromXML(lbl, reader);
        BigInteger c = CryptoFactoryC.stringToDefaultBigInt(Util.unescapeString(Util.readSimpleTag(lbl, reader, "c")));
        BigInteger w = CryptoFactoryC.stringToDefaultBigInt(Util.unescapeString(Util.readSimpleTag(lbl, reader, "w")));
        BigInteger r = CryptoFactoryC.stringToDefaultBigInt(Util.unescapeString(Util.readSimpleTag(lbl, reader, "r")));
        BigInteger u = CryptoFactoryC.stringToDefaultBigInt(Util.unescapeString(Util.readSimpleTag(lbl, reader, "u")));

        Util.swallowEndTag(lbl, reader, "elGamalProofDVR");
        return new ElGamalProofDVRC(e, eprime, c, w, r, u);
    }
}
