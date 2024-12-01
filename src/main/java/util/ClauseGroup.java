package util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import encryption.ElgamalScheme;

public class ClauseGroup {
    private LogicOpType operation;
    private List<CertType> certList;
    private Integer numRequired;
    private Integer numAvailable;

    public ClauseGroup(LogicOpType op, CertType cert, Integer numRequired, Integer numAvailable) {
        this.operation = op;
        this.certList = new ArrayList<>();
        this.certList.add(cert);
        this.numRequired = numRequired;
        this.numAvailable = numAvailable;
    }

    public void addCertToGroup(CertType cert) {
        this.certList.add(cert);
    }
    public void incrementNumAvailable() {
        this.numAvailable++;
    }
    public LogicOpType getOperation() {
        return this.operation;
    }
    public List<CertType> getCertList() {
        return this.certList;
    }
    public Integer getNumRequired() {
        return this.numRequired;
    }
    public Integer getNumAvailable() {
        return this.numAvailable;
    }
    public BigInteger processGroup(Clause clause, Set<Integer> groupCodes, ElgamalScheme scheme) {
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
                return subkey_xor;
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
                            return BigInteger.valueOf(-1);
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
                return runningTotal;
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
                return subkey_or;
            case XOFN:
                // for XOFN each cert in the group should have the same subkey and unique groups
                BigInteger subkey_xofn = scheme.getGenerator(this.numAvailable);
                BigInteger total_key = subkey_xofn.modPow(BigInteger.valueOf(this.numRequired), scheme.getP());
                int code2;
                for (CertType cert : this.certList) {
                    do {
                        code2 = r.nextInt();
                    } while (groupCodes.contains(code2));
                    // add group code to list of group codes so we don't use it again
                    groupCodes.add(code2);
                    // add clause item to final clause
                    ClauseItem item = new ClauseItem(cert, subkey_xofn, code2);
                    clause.addItem(item);
                }
                return total_key;
            case NA:
                // for NA each cert in the group should have their own subkey and group
                BigInteger subkey_na = BigInteger.valueOf(-1);
                if (this.certList.size() != 1) {
                    System.err.println("ERROR: NA group has more than 1 cert, make NA attributes different group numbers");
                    return subkey_na;
                }
                for (CertType cert : this.certList) {
                    subkey_na = scheme.randomKey();
                    int code3;
                    do {
                        code3 = r.nextInt();
                    } while (groupCodes.contains(code3));
                    // add group code to list of group codes so we don't use it again
                    groupCodes.add(code3);
                    // add clause item to final clause
                    ClauseItem item = new ClauseItem(cert, subkey_na, code3);
                    clause.addItem(item);
                }
                return subkey_na;
            default:
                return BigInteger.valueOf(-1);
        }
    }

}