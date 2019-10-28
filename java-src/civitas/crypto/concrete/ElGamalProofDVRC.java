/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */ 
package civitas.crypto.concrete;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import jif.lang.Label;
import jif.lang.LabelUtil;
import civitas.common.Util;
import civitas.crypto.*;
import civitas.util.CivitasBigInteger;

public class ElGamalProofDVRC implements ElGamalProofDVR {
    private final ElGamalCiphertextC e;
    private final ElGamalCiphertextC eprime;
    public final CivitasBigInteger c;
    public final CivitasBigInteger w;
    public final CivitasBigInteger r;
    public final CivitasBigInteger u;

    public ElGamalProofDVRC(ElGamalCiphertextC e, ElGamalCiphertextC eprime, 
            CivitasBigInteger c, CivitasBigInteger w, CivitasBigInteger r, CivitasBigInteger u) {
        this.e = e;
        this.eprime = eprime;
        this.c = c;
        this.w = w;
        this.r = r;
        this.u = u;
    }
    
    public static ElGamalProofDVRC constructProof(ElGamalCiphertextC e, ElGamalCiphertextC eprime, 
            ElGamalPublicKeyC key, ElGamalPublicKeyC verifierKey,
            CivitasBigInteger zeta) {
        CryptoFactoryC factory = CryptoFactoryC.singleton();
        
        // check that the inputs are correct
//        if (!factory.elGamalReencrypt(key, e, new ElGamalReencryptFactorC(zeta)).equals(eprime)) {
//            throw new CryptoError("Incorrect value for zeta passed in"); 
//        }
        
        ElGamalParametersC ps = (ElGamalParametersC)key.getParams();
        CivitasBigInteger d = CryptoAlgs.randomElement(ps.q);
        CivitasBigInteger w = CryptoAlgs.randomElement(ps.q);
        CivitasBigInteger r = CryptoAlgs.randomElement(ps.q);
        CivitasBigInteger h = key.y;
        CivitasBigInteger hv = verifierKey.y;
        CivitasBigInteger a = ps.g.modPow(d, ps.p);
        CivitasBigInteger b = h.modPow(d, ps.p);
        CivitasBigInteger s = ps.g.modPow(w, ps.p).modMultiply(hv.modPow(r, ps.p), ps.p);
        List<CivitasBigInteger> l = new ArrayList<CivitasBigInteger>();
        l.add(e.a);
        l.add(e.b);
        l.add(eprime.a);
        l.add(eprime.b);
        l.add(a);
        l.add(b);
        l.add(s);
        CivitasBigInteger c = factory.hashToBigInt(factory.hash(l)).mod(ps.q);

        CivitasBigInteger u = d.modAdd(zeta.modMultiply(c.modAdd(w, ps.q), ps.q), ps.q);
        
        return new ElGamalProofDVRC(e, eprime, c, w, r, u);
        
    }
    
    public static ElGamalProofDVRC fakeProof(ElGamalCiphertextC e, ElGamalCiphertextC et, ElGamalPublicKeyC key, ElGamalPublicKeyC verifierKey, ElGamalPrivateKeyC verifierPrivKey) {
        CryptoFactoryC factory = CryptoFactoryC.singleton();

        ElGamalParametersC ps = (ElGamalParametersC)key.getParams();
        //CivitasBigInteger hv = verifierKey.y;
        CivitasBigInteger zv = verifierPrivKey.x;

        CivitasBigInteger h = key.y;
        CivitasBigInteger x = e.a;
        CivitasBigInteger y = e.b;
        CivitasBigInteger xt = et.a;
        CivitasBigInteger yt = et.b;

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
        CivitasBigInteger alpha = CryptoAlgs.randomElement(ps.q);
        CivitasBigInteger beta = CryptoAlgs.randomElement(ps.q);
        CivitasBigInteger ut = CryptoAlgs.randomElement(ps.q);
        
        CivitasBigInteger at = ps.g.modPow(ut, ps.p).modDivide(xt.modDivide(x, ps.p).modPow(alpha, ps.p), ps.p);
        CivitasBigInteger bt = h.modPow(ut, ps.p).modDivide(yt.modDivide(y, ps.p).modPow(alpha, ps.p), ps.p);
        CivitasBigInteger st = ps.g.modPow(beta, ps.p);

        List<CivitasBigInteger> l = new ArrayList<CivitasBigInteger>();
        l.add(e.a);
        l.add(e.b);
        l.add(et.a);
        l.add(et.b);
        l.add(at);
        l.add(bt);
        l.add(st);
        CivitasBigInteger ct = factory.hashToBigInt(factory.hash(l)).mod(ps.q);
        
        CivitasBigInteger wt = alpha.modSubtract(ct, ps.q);
        CivitasBigInteger rt = beta.modSubtract(wt, ps.q).modDivide(zv, ps.q);
        
        return new ElGamalProofDVRC(e, et, ct, wt, rt, ut);

        
    }

    public boolean verify(ElGamalPublicKey K, ElGamalPublicKey verifierKey) {
        CryptoFactoryC factory = CryptoFactoryC.singleton();

        ElGamalParametersC ps = (ElGamalParametersC)K.getParams();
        ElGamalPublicKeyC key = (ElGamalPublicKeyC)K;
        
        CivitasBigInteger hv = ((ElGamalPublicKeyC)verifierKey).y;
        CivitasBigInteger h = key.y;
        CivitasBigInteger x = e.a;
        CivitasBigInteger y = e.b;
        CivitasBigInteger xp = eprime.a;
        CivitasBigInteger yp = eprime.b;

        /*
         * a' = (g^u) / ((x'/x)^(c+w))
         * b' = (h^u) / ((y'/y)^(c+w))
         * s' = (g^w)*((h_v)^r)
         * c' = hash(E||a'||b'||s') 
         */
        
        CivitasBigInteger ap = ps.g.modPow(u, ps.p).modDivide(xp.modDivide(x, ps.p).modPow(c.modAdd(w, ps.q), ps.p), ps.p);
        CivitasBigInteger bp = h.modPow(u, ps.p).modDivide(yp.modDivide(y, ps.p).modPow(c.modAdd(w, ps.q), ps.p), ps.p);
        CivitasBigInteger sp = ps.g.modPow(w, ps.p).modMultiply(hv.modPow(r, ps.p), ps.p);
        
        List<CivitasBigInteger> l = new ArrayList<CivitasBigInteger>();
        l.add(e.a);
        l.add(e.b);
        l.add(eprime.a);
        l.add(eprime.b);
        l.add(ap);
        l.add(bp);
        l.add(sp);
        CivitasBigInteger cp = factory.hashToBigInt(factory.hash(l)).mod(ps.q);
        
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
        Util.escapeString(CryptoFactoryC.bigIntToString(c), lbl, s); 
        s.print("</c>");
        s.print("<w>"); 
        Util.escapeString(CryptoFactoryC.bigIntToString(w), lbl, s); 
        s.print("</w>");
        s.print("<r>"); 
        Util.escapeString(CryptoFactoryC.bigIntToString(r), lbl, s); 
        s.print("</r>");
        s.print("<u>"); 
        Util.escapeString(CryptoFactoryC.bigIntToString(u), lbl, s); 
        s.print("</u>");
        s.print("</elGamalProofDVR>");
    }

    public static ElGamalProofDVR fromXML(Label lbl, Reader reader) throws IllegalArgumentException, IOException {
        Util.swallowTag(lbl, reader, "elGamalProofDVR");
        ElGamalCiphertextC e = (ElGamalCiphertextC)CryptoFactoryC.singleton().elGamalCiphertextFromXML(lbl, reader);
        ElGamalCiphertextC eprime = (ElGamalCiphertextC)CryptoFactoryC.singleton().elGamalCiphertextFromXML(lbl, reader);
        CivitasBigInteger c = CryptoFactoryC.stringToBigInt(Util.unescapeString(Util.readSimpleTag(lbl, reader, "c")));
        CivitasBigInteger w = CryptoFactoryC.stringToBigInt(Util.unescapeString(Util.readSimpleTag(lbl, reader, "w")));
        CivitasBigInteger r = CryptoFactoryC.stringToBigInt(Util.unescapeString(Util.readSimpleTag(lbl, reader, "r")));
        CivitasBigInteger u = CryptoFactoryC.stringToBigInt(Util.unescapeString(Util.readSimpleTag(lbl, reader, "u")));

        Util.swallowEndTag(lbl, reader, "elGamalProofDVR");
        return new ElGamalProofDVRC(e, eprime, c, w, r, u);
    }

    

}
