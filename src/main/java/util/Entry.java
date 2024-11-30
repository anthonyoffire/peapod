package util;

import java.io.Serializable;
import java.math.BigInteger;

public class Entry implements Serializable{
    private Clause clause;
    private BigInteger ciphertext;
    private static final long serialVersionUID = 1000L;

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
