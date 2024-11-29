package server;

import util.Clause;

public class Entry {
    private Clause clause;
    private String ciphertext;

    public Entry(Clause clause, String ciphertext) {
        this.clause = clause;
        this.ciphertext = ciphertext;
    }

    public Clause getClause() {
        return clause;
    }
    public String getCiphertext() {
        return ciphertext;
    }
    
}
