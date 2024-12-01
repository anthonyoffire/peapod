package server;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

import encryption.ElgamalScheme;
import encryption.SymScheme;
import util.CertType;
import util.Certificate;
import util.Clause;
import util.ClauseItem;
import util.Entry;

/* Functionality for all jobs */
public abstract class Job {
    private int jid;
    public Job(){
        this.jid = new Random().nextInt(1000000);
    }
    public int getJid(){
        return jid;
    };
    // execute: override this method
    public Object execute(
        Map<UUID, Entry> entries, 
        BigInteger K, 
        ElgamalScheme elgamalScheme, 
        Map<String, Map<CertType, BigInteger>> userTransKeys){
            return null;
    };
}
class PostJob extends Job {
    private UUID uuid;
    private Clause clause;
    private BigInteger ciphertext;
    private String user;
    private SymScheme symScheme;
    

    public PostJob(String user, Clause clause, BigInteger ciphertext, SymScheme symScheme){
        super();
        this.uuid = UUID.randomUUID();
        this.clause = clause;
        this.ciphertext = ciphertext;
        this.user = user;
        this.symScheme = symScheme;
    }
    @Override
    public Object execute(
        Map<UUID, Entry> entries, 
        BigInteger K, 
        ElgamalScheme elgamalScheme, 
        Map<String, Map<CertType, BigInteger>> userTransKeys){
            for (ClauseItem item: clause.getClause()){
                CertType type = item.getCertType();
                BigInteger message = item.getVal();
                BigInteger key = userTransKeys.get(user)
                    .get(type);
                item.setVal(elgamalScheme.encrypt(key, message));
            }
            entries.put(uuid, new Entry(clause, ciphertext, symScheme));
            return uuid;
    }
}
class GetEntryJob extends Job {
    private UUID uuid;
    private List<Certificate> userCerts;
    private String user;

    public GetEntryJob(String user, UUID uuid, List<Certificate> certs){
        super();
        this.uuid = uuid;
        this.userCerts = certs;
    }
    @Override
    public Entry execute(
        Map<UUID, Entry> entries, 
        BigInteger K, 
        ElgamalScheme elgamalScheme, 
        Map<String, Map<CertType, BigInteger>> userTransKeys){
            Entry storedEntry = entries.get(uuid);
            Clause storedClause = storedEntry.getClause();
            List<ClauseItem> storedItems = storedClause.getClause();
            List<ClauseItem> validItems = new ArrayList<>();

            // Match valid certs
            for(Certificate userCert: userCerts){
                CertType userType = userCert.getType();
                for(ClauseItem item: storedItems){
                    CertType storedType = item.getCertType();
                    if(userType.equals(storedType)){
                        ClauseItem clonedItem = new ClauseItem(storedType, item.getVal(), item.getGroupCode());
                        validItems.add(clonedItem);
                    }
                }
            }

            // Re-encrypt valid items for user
            for(ClauseItem item: validItems){
                CertType type = item.getCertType();
                BigInteger message = item.getVal();
                BigInteger key = userTransKeys.get(user)
                    .get(type);
                item.setVal(elgamalScheme.encrypt(key, message));
            }

            // Blind
            int n = validItems.size();
            BigInteger p = elgamalScheme.getP();
            BigInteger multiple = BigInteger.ONE;
            BigInteger val;
            List<BigInteger> blindingFactors = new ArrayList<>();
            
            // Generate n - 1 random numbers and multiply them 
            for(int i=1; i<n; i++){
                val = elgamalScheme.randomKey();
                blindingFactors.add(val);
                multiple.multiply(val).mod(p);
            }

            // Calc inverse
            BigInteger inverse = multiple.modInverse(p);
            blindingFactors.add(inverse);
            
            // For each valid item, encrypt a blinding factor and multiply it
            for(ClauseItem item: validItems){
                CertType type = item.getCertType();
                BigInteger bf = blindingFactors.remove(0);
                BigInteger key = userTransKeys.get(user)
                    .get(type);
                bf = elgamalScheme.encrypt(key, bf);
                val = item.getVal()
                    .multiply(bf)
                    .mod(p);
                item.setVal(val);
            }
            return new Entry(new Clause(validItems), storedEntry.getCiphertext(), storedEntry.getSymScheme());
    }
}
class GetKeysJob extends Job {
    String name;
    public GetKeysJob(String name){
        super();
        this.name = name;
    }
    @Override
    public Map<CertType, BigInteger> execute(
        Map<UUID, Entry> entries, 
        BigInteger K, 
        ElgamalScheme elgamalScheme, 
        Map<String, Map<CertType, BigInteger>> userTransKeys){
            Map<CertType, BigInteger> userKeys = new HashMap<>();
		Map<CertType, BigInteger> transKeys = new HashMap<>();
		BigInteger p = elgamalScheme.getP();
		BigInteger userKey, transKey;

		for(CertType type:CertType.values()){
			userKey = elgamalScheme.randomKey();
			transKey = K.subtract(userKey).mod(p.subtract(new BigInteger("1")));
			userKeys.put(type, userKey);
			transKeys.put(type, transKey);
		}
		userTransKeys.put(name,transKeys);
		return userKeys;
    }
}
class DeleteJob extends Job {

    public DeleteJob(){
        super();
    }
    @Override
    public Object execute(Map<UUID, Entry> entries, 
        BigInteger K, 
        ElgamalScheme elgamalScheme, 
        Map<String, Map<CertType, BigInteger>> userTransKeys){
            /* DELETE FUNCTIONALITY GOES HERE */
            return "DeleteJob Result";
    }
}
