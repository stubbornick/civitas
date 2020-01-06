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
import civitas.common.CiphertextList;
import civitas.common.Util;
import civitas.crypto.CryptoHashableList;
import civitas.crypto.ElGamalCiphertext;
import civitas.crypto.ElGamalProof1OfL;
import civitas.crypto.ElGamalPublicKey;
import civitas.util.CivitasBigInteger;

public class ElGamalProof1OfLC implements ElGamalProof1OfL {
    final int L;
    final BigInteger[] dvs;
    final BigInteger[] rvs;

    public ElGamalProof1OfLC(int L, BigInteger[] dvs, BigInteger[] rvs) {
        this.L = L;
        this.dvs = dvs;
        this.rvs = rvs;
        if (dvs == null || rvs == null || dvs.length != L || rvs.length != L) {
            throw new IllegalArgumentException("Bad args");
        }
    }

    public static ElGamalProof1OfLC constructProof(ElGamalPublicKeyC key,
            ElGamalCiphertext[] ciphertexts,
            int L,
            int choice,
            ElGamalCiphertextC m,
            ElGamalReencryptFactorC factor) {
        CryptoFactoryC factory = CryptoFactoryC.singleton();

        ElGamalParametersC ps = (ElGamalParametersC)key.params;
        ECPoint u = m.a;
        ECPoint v = m.b;
        BigInteger r = factor.r;

        ElGamalCiphertextC[] ms = new ElGamalCiphertextC[L];
        for (int i = 0; i < L; i++) {
            ms[i] = (ElGamalCiphertextC)ciphertexts[i];
        }

        // choose d1 .. dL, and r1 ... rL at random.
        BigInteger[] ds = new BigInteger[L];
        BigInteger[] rs = new BigInteger[L];
        for (int i = 0; i < L; i++) {
            ds[i] = CryptoAlgs.randomElementDefault(ps.params.getN());
            rs[i] = CryptoAlgs.randomElementDefault(ps.params.getN());
        }

        // Save for easy using
        ECPoint G = ps.params.getG();
        BigInteger N = ps.params.getN();

        // compute a_i's and b_i's
        ECPoint[] as = new ECPoint[L];
        ECPoint[] bs = new ECPoint[L];
        for (int i = 0; i < L; i++) {
            as[i] = ms[i].a.subtract(u).multiply(ds[i]).add(G.multiply(rs[i]));
            bs[i] = ms[i].b.subtract(v).multiply(ds[i]).add(key.y.multiply(rs[i]));
        }

        CryptoHashableList env = new CryptoHashableList(2 + 4*L);
        env.add(u);
        env.add(v);
        for (int i = 0; i < L; i++) {
            env.add(ms[i].a);
            env.add(ms[i].b);
            env.add(as[i]);
            env.add(bs[i]);
        }
        BigInteger c = factory.hashToDefaultBigInt(factory.hash(env)).mod(N);
        BigInteger w = CivitasBigInteger.modAdd(CivitasBigInteger.modMultiply(CivitasBigInteger.modNegate(r, N), ds[choice], N), rs[choice], N);
        BigInteger sum = BigInteger.ZERO;
        for (int i = 0; i < L; i++) {
            if (i != choice) {
                sum = CivitasBigInteger.modAdd(sum, ds[i], N);
            }
        }
        BigInteger dprimet = CivitasBigInteger.modSubtract(c, sum, N);
        BigInteger rprimet = CivitasBigInteger.modAdd(w, CivitasBigInteger.modMultiply(r, dprimet, N), N);

        BigInteger[] dvs = new BigInteger[L];
        BigInteger[] rvs = new BigInteger[L];
        for (int i = 0; i < L; i++) {
            if (i != choice) {
                dvs[i] = ds[i];
                rvs[i] = rs[i];
            }
            else {
                dvs[i] = dprimet;
                rvs[i] = rprimet;
            }
        }

        return new ElGamalProof1OfLC(L, dvs, rvs);
    }
    public boolean verify(ElGamalPublicKey pubKey, CiphertextList ciphertexts, int L, ElGamalCiphertext msg) {
        if (this.L != L) return false;
        ElGamalCiphertextC m = (ElGamalCiphertextC)msg;
        ECPoint u = m.a;
        ECPoint v = m.b;
        ElGamalPublicKeyC key = (ElGamalPublicKeyC)pubKey;
        ElGamalParametersC ps = (ElGamalParametersC)key.params;
        ElGamalCiphertextC[] ms = new ElGamalCiphertextC[L];

        for (int i = 0; i < L; i++) {
            ms[i] = (ElGamalCiphertextC)ciphertexts.get(i);
        }

        CryptoFactoryC factory = CryptoFactoryC.singleton();
        ECPoint[] as = new ECPoint[L];
        ECPoint[] bs = new ECPoint[L];
        BigInteger sum = BigInteger.ZERO;
        for (int i = 0; i < L; i++) {
            as[i] = (ms[i].a.subtract(u)).multiply(dvs[i]).add(ps.params.getG().multiply(rvs[i]));
            bs[i] = (ms[i].b.subtract(v)).multiply(dvs[i]).add(key.y.multiply(rvs[i]));
            sum = CivitasBigInteger.modAdd(sum, dvs[i], ps.params.getN());
        }

        // construct the hash of the environment
        CryptoHashableList env = new CryptoHashableList(2 + 4*L);
        env.add(u);
        env.add(v);
        for (int i = 0; i < L; i++) {
            env.add(ms[i].a);
            env.add(ms[i].b);
            env.add(as[i]);
            env.add(bs[i]);
        }
        BigInteger c = factory.hashToDefaultBigInt(factory.hash(env)).mod(ps.params.getN());
        return sum.equals(c);
    }
    public String toXML() {
        StringWriter sb = new StringWriter();
        toXML(LabelUtil.singleton().noComponents(), new PrintWriter(sb));
        return sb.toString();
    }
    public void toXML(Label lbl, PrintWriter s) {
        s.print("<elGamalProof1OfL>");
        s.print("<size>");
        s.print(L);
        s.print("</size>");
        for (int i = 0; i < L; i++) {
            s.print("<dv>");
            if (dvs[i] != null) Util.escapeString(CryptoFactoryC.defaultBigIntToString(this.dvs[i]), lbl, s);
            s.print("</dv>");
        }
        for (int i = 0; i < L; i++) {
            s.print("<rv>");
            if (rvs[i] != null) Util.escapeString(CryptoFactoryC.defaultBigIntToString(this.rvs[i]), lbl, s);
            s.print("</rv>");
        }
        s.print("</elGamalProof1OfL>");
    }
    public boolean equals(ElGamalProof1OfL p) {
        if (p instanceof ElGamalProof1OfLC) {
            ElGamalProof1OfLC that = (ElGamalProof1OfLC)p;
            if (this.L != that.L) return false;

            for (int i = 0; i < L; i++) {
                try {
                    if (!dvs[i].equals(that.dvs[i])) return false;
                    if (!rvs[i].equals(that.rvs[i])) return false;
                }
                catch (NullPointerException e) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    public static ElGamalProof1OfLC fromXML(Label lbl, Reader r) throws IllegalArgumentException, IOException {
        Util.swallowTag(lbl, r, "elGamalProof1OfL");
        int L = Util.readSimpleIntTag(lbl, r, "size");
        BigInteger[] dvs = new BigInteger[L];
        BigInteger[] rvs = new BigInteger[L];
        for (int i = 0; i < L; i++) {
            dvs[i] = CryptoFactoryC.stringToDefaultBigInt(Util.unescapeString(Util.readSimpleTag(lbl, r, "dv")));
        }
        for (int i = 0; i < L; i++) {
            rvs[i] = CryptoFactoryC.stringToDefaultBigInt(Util.unescapeString(Util.readSimpleTag(lbl, r, "rv")));
        }

        Util.swallowEndTag(lbl, r, "elGamalProof1OfL");
        return new ElGamalProof1OfLC(L, dvs, rvs);
    }

}
