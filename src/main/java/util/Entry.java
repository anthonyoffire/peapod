package util;

import java.math.BigInteger;

public class Entry {
    private Clause clause;
    private BigInteger ciphertext;

    public Entry(Clause clause, BigInteger ciphertext) {
        this.clause = clause;
        this.ciphertext = ciphertext;
    }

    public Clause getClause() {
        return clause;
    }
    public BigInteger getCiphertext() {
        return ciphertext;
    }
    
}
