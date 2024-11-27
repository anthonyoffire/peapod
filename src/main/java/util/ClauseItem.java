package util;

public class ClauseItem {

    private String certType;
    private int val;

    public ClauseItem(String certType, int val) {
        this.certType = certType;
        this.val = val;
    }
    public String getCertType() {
        return certType;
    }
    public int getVal() {
        return val;
    }
}
