package util;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;

public class Clause implements Serializable{
    private List<ClauseItem> clause;
    private static final long serialVersionUID = 2000L;

    public Clause(List<ClauseItem> clause) {
        this.clause = clause;
    }

    public List<ClauseItem> getClause() {
        return clause;
    }
    public void addItem(ClauseItem item){
        clause.add(item);
    }
    public int getCodeFromCert(CertType cert) {
        for (ClauseItem item : this.clause) {
            if (item.getCertType() == cert) {
                return item.getGroupCode();
            }
        }
        return -1;
    }
    public BigInteger getValFromCert(CertType cert) {
        for (ClauseItem item : this.clause) {
            if (item.getCertType() == cert) {
                return item.getCipherPair()[1];
            }
        }
        return null;
    }
}

