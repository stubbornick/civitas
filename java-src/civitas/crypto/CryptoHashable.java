package civitas.crypto;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class CryptoHashable {
    public final byte[] bytes;

    public CryptoHashable(String s) {
        this.bytes = s.getBytes();
    }

    public CryptoHashable(ECPoint p) {
        this.bytes = p.getEncoded(true);
    }

    public CryptoHashable(BigInteger i) {
        this.bytes = i.toByteArray();
    }

    public CryptoHashable(byte[] raw) {
        this.bytes = raw;
    }
}
