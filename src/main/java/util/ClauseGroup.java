package util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import elgamal.ElgamalScheme;

public class ClauseGroup {
    private LogicOpType operation;
    private List<CertType> certList;

    public ClauseGroup(LogicOpType op, CertType cert) {
        this.operation = op;
        this.certList = new ArrayList<>();
        this.certList.add(cert);
    }

    public void addCertToGroup(CertType cert) {
        this.certList.add(cert);
    }
    public LogicOpType getOperation() {
        return this.operation;
    }
    public List<CertType> getCertList() {
        return this.certList;
    }
    public Integer processGroup(Clause clause, Set<Integer> groupCodes, ElgamalScheme scheme) {
        SecureRandom r = new SecureRandom();
        switch(this.operation) {
            case XOR:
                // for XOR each cert in the group should have the same subkey
                BigInteger subkey_xor = scheme.randomKey();
                for (CertType cert : this.certList) {
                    // each one needs to have a unique group code so the decrypter will use all available
                    int code;
                    do {
                        code = r.nextInt();
                    } while (groupCodes.contains(code));
                    // add group code to list of group codes so we don't use it again
                    groupCodes.add(code);
                    // add clause item to final clause
                    ClauseItem item = new ClauseItem(cert, subkey_xor, code);
                    clause.addItem(item);
                }
                return 0;
            case ANDNAND:
                // for ANDNAND each of the keys multiplied together need to equal 1 mod p
                BigInteger runningTotal = BigInteger.ONE;
                for (int i = 0; i < this.certList.size(); i++) {
                    BigInteger subkey_andnand;
                    if (i == this.certList.size()-1) {
                        // for last subkey make it the inverse of the other keys multiplied together
                        try {
                            subkey_andnand = runningTotal.modInverse(scheme.getP());
                        } catch (ArithmeticException e) {
                            System.err.println("First subkeys do not have a valid inverse for last subkey of ANDNAND group");
                            return -1;
                        }
                    } else {
                        // for first in the groups pick a random subkey
                        subkey_andnand = scheme.randomKey();
                    }
                    // multiply running total by new subkey, we use this value to calc inverse for last subkey
                    runningTotal = runningTotal.multiply(subkey_andnand).mod(scheme.getP());
                    // each one needs to have a unique group code so the decrypter will use all available
                    int code;
                    do {
                        code = r.nextInt();
                    } while (groupCodes.contains(code));
                    // add group code to list of group codes so we don't use it again
                    groupCodes.add(code);
                    ClauseItem item = new ClauseItem(this.certList.get(i), subkey_andnand, code);
                    clause.addItem(item);
                }
                assert runningTotal.equals(BigInteger.ONE) : "ANDNAND: keys do not multiply to 1 mod p despite finding inverse";
                return 0;
            case OR:
                // for OR each cert in the group should have the same subkey and also the same group
                BigInteger subkey_or = scheme.randomKey();
                int code;
                do {
                    code = r.nextInt();
                } while (groupCodes.contains(code));
                // add group code to list of group codes so we don't use it again
                groupCodes.add(code);
                for (CertType cert : this.certList) {
                    // add clause item to final clause
                    ClauseItem item = new ClauseItem(cert, subkey_or, code);
                    clause.addItem(item);
                }
                return 0;
            case XOFN:
                // TODO
            default:
                return -1;
        }
    }

}