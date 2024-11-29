package util;

public class Certificate {
    private CertType certType;

    public Certificate(CertType certType) {
        this.certType = certType;
    }

    public CertType getType() {
        return certType;
    }
}
