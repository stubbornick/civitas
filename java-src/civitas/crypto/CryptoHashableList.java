package civitas.crypto;

import java.math.BigInteger;
import java.util.ArrayList;

import org.bouncycastle.math.ec.ECPoint;

public class CryptoHashableList extends ArrayList<CryptoHashable> {
    public CryptoHashableList() {
        super();
    }

    public CryptoHashableList(int size) {
        super(size);
    }

    public boolean add(String x) {
        return super.add(new CryptoHashable(x));
    }

    public boolean add(ECPoint x) {
        return super.add(new CryptoHashable(x));
    }

    public boolean add(BigInteger x) {
        return super.add(new CryptoHashable(x));
    }

    public boolean add(byte[] x) {
        return super.add(new CryptoHashable(x));
    }
}
