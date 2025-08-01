package encryption;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ElgamalScheme implements Serializable{
    private BigInteger p, g;
    private int bitlen;
    private static final long serialVersionUID = 5000L;

    public ElgamalScheme(int bitLen){
        this.bitlen = bitLen;
        SecureRandom r = new SecureRandom();
        p = BigInteger.probablePrime(bitLen, r);
        // find g < p
        do{
            g = BigInteger.probablePrime(bitlen, r);
        } while (g.compareTo(p) != -1);
    }
    public BigInteger getG() {
        return g;
    }
    public BigInteger getP() {
        return p;
    }
    public BigInteger decrypt(BigInteger[] cipherpair){
        BigInteger pubkey = cipherpair[0];
		BigInteger inverse = pubkey.modInverse(p);
        return cipherpair[1].multiply(inverse).mod(p);
    }
    public BigInteger[] encrypt(BigInteger privkey, BigInteger message){
        BigInteger pubk = g.modPow(privkey, p);
        return new BigInteger[]{
            pubk, 
            message.multiply(pubk).mod(p)
        };
    }
    public BigInteger[] reEncrypt(BigInteger privkey, BigInteger[] cipherpair){
        BigInteger pubk = g.modPow(privkey, p);
        return new BigInteger[]{
            cipherpair[0].multiply(pubk).mod(p),
            cipherpair[1].multiply(pubk).mod(p)
        };
    }
    public BigInteger[] preDecrypt(BigInteger privkey, BigInteger[] cipherpair){
        BigInteger pubk = g.modPow(privkey, p);
        BigInteger inverse = pubk.modInverse(p);
        return new BigInteger[]{
            cipherpair[0].multiply(inverse).mod(p),
            cipherpair[1].multiply(inverse).mod(p)
        };
    }
    public BigInteger[] homomorphicMultiply(BigInteger[] pair1, BigInteger[] pair2){
        return new BigInteger[]{
            pair1[0].multiply(pair2[0]).mod(p),
            pair1[1].multiply(pair2[1]).mod(p)
        };
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
