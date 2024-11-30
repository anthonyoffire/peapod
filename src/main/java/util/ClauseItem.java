package util;

import java.math.BigInteger;

public class ClauseItem {

    private CertType certType;
    private BigInteger val;
    private int groupCode;

    public ClauseItem(CertType certType, BigInteger val, int groupCode) {
        this.certType = certType;
        this.val = val;
        this.groupCode = groupCode;
    }
    public CertType getCertType() {
        return certType;
    }
    public BigInteger getVal() {
        return val;
    }
    public int getGroupCode() {
        return groupCode;
    }
    public void setVal(BigInteger newVal){
        this.val = newVal;
    }
    public void setGroupCode(int newCode){
        this.groupCode = newCode;
    }
}
