package elgamal;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ElgamalScheme {
    private BigInteger p, g;
    private int bitlen;

    public ElgamalScheme(int bitLen){
        this.bitlen = bitLen;
        SecureRandom r = new SecureRandom();
        p = BigInteger.probablePrime(bitLen, r);
        g = new BigInteger("2");
    }
    public BigInteger getG() {
        return g;
    }
    public BigInteger getP() {
        return p;
    }
    public BigInteger encrypt(BigInteger key, BigInteger m){
        BigInteger pubk = g.modPow(key, p);
        return m.multiply(pubk).mod(p);
    }
    public BigInteger randomKey(){
        return new BigInteger(bitlen-1, new SecureRandom());
    }
}
