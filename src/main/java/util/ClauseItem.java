package util;

import java.io.Serializable;
import java.math.BigInteger;

public class ClauseItem implements Serializable{

    private CertType certType;
    private BigInteger[] cipherpair;
    private int groupCode;
    private static final long serialVersionUID = 3000L;

    public ClauseItem(CertType certType, BigInteger[] cipherpair, int groupCode) {
        this.certType = certType;
        this.cipherpair = cipherpair;
        this.groupCode = groupCode;
    }
    public CertType getCertType() {
        return certType;
    }
    public BigInteger[] getCipherPair() {
        return cipherpair;
    }
    public int getGroupCode() {
        return groupCode;
    }
    public void setCipherPair(BigInteger[] cipherpair){
        this.cipherpair = cipherpair;
    }
    public void setGroupCode(int newCode){
        this.groupCode = newCode;
    }
}
