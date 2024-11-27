package util;

public class ClauseItem {

    private String certType;
    
    public ClauseItem(String certType, int val) {
        this.certType = certType;
        this.val = val;
    }
    public String getCertType() {
        return certType;
    }
    private int val;
    public int getVal() {
        return val;
    }
}
