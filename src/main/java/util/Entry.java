package util;

import java.io.Serializable;
import java.math.BigInteger;

import encryption.SymScheme;

public class Entry implements Serializable{
    private Clause clause;
    private SymScheme symScheme;
    private BigInteger ciphertext;
    private static final long serialVersionUID = 1000L;

    public Entry(Clause clause, BigInteger ciphertext, SymScheme symScheme) {
        this.clause = clause;
        this.ciphertext = ciphertext;
        this.symScheme = symScheme;
    }

    public Clause getClause() {
        return clause;
    }
    public BigInteger getCiphertext() {
        return ciphertext;
    }
    public SymScheme getSymScheme(){
        return symScheme;
    }
    
}
