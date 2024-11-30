package util;
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
}

