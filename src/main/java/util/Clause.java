package util;
import java.math.BigInteger;
import java.util.List;

public class Clause {
    private List<ClauseItem> clause;

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
                return item.getVal();
            }
        }
        return null;
    }
}

