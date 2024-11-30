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
    public BigInteger encrypt(BigInteger key, BigInteger message){
        BigInteger pubk = g.modPow(key, p);
        return message.multiply(pubk).mod(p);
    }
    public BigInteger randomKey(){
        // Always returns a value from 2 to p-2
        SecureRandom r = new SecureRandom();
        BigInteger key;
        do{
            key = new BigInteger(bitlen-1, r);
        } while (key.compareTo(BigInteger.TWO) < 0 || key.compareTo(p.subtract(BigInteger.TWO)) > 0);
        return key;
    }
}
