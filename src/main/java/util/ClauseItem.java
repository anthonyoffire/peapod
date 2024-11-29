package util;

import java.math.BigInteger;

public class ClauseItem {

    private CertType certType;
    private BigInteger val;

    public ClauseItem(CertType certType, BigInteger val) {
        this.certType = certType;
        this.val = val;
    }
    public CertType getCertType() {
        return certType;
    }
    public BigInteger getVal() {
        return val;
    }
}
