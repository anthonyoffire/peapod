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
    public BigInteger getGenerator(int groupSize) {
        BigInteger generator;
        int loops = 0;
        do {
            // pick a random number
            generator = this.randomKey();
            int order = 0;
            // loop over powers starting at one until we either have a subgroup of more than group size
            // or our generator to the power equals one mod p and we need to pick a new one.
            for (BigInteger power = BigInteger.ONE; power.compareTo(this.getP()) < 0; power.add(BigInteger.ONE)) {
                // checking to see if g^power mod p == 1.
                // if so we know the next power will be g again so we stop. We also don't include 1 in our subgroup count
                if (generator.modPow(power, this.getP()).equals(BigInteger.ONE)) {
                    break;
                } else {
                    order++;
                }
                if (order > (groupSize+1)) {
                    return generator;
                }
            }
            // check to see if we can find a generator easily
            loops++;
            if (loops==100) {
                return null;
            }
        } while (true);
    }
}
