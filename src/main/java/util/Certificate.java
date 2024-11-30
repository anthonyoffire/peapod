package util;

import java.io.Serializable;

public class Certificate implements Serializable{
    private CertType certType;
    private static final long serialVersionUID = 4000L;

    public Certificate(CertType certType) {
        this.certType = certType;
    }

    public CertType getType() {
        return certType;
    }
}
