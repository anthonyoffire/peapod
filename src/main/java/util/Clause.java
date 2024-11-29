package util;
import java.util.ArrayList;

public class Clause {
    private ArrayList<ClauseItem> clause;

    public Clause(ArrayList<ClauseItem> clause) {
        this.clause = clause;
    }

    public ArrayList<ClauseItem> getClause() {
        return clause;
    }
    public void addItem(ClauseItem item){
        clause.add(item);
    }
}

