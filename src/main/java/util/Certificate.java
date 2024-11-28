package util;

public class Certificate {
    private CertType certType;

    public Certificate(CertType certType) {
        this.certType = certType;
    }

    public String getType() {
        return certType;
    }
}
