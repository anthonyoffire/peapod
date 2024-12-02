package server;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
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
            return 1;
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
                BigInteger[] cipherpair = item.getCipherPair();
                BigInteger key = userTransKeys.get(user)
                    .get(type);
                item.setCipherPair(elgamalScheme.reEncrypt(key, cipherpair));
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
        this.user = user;
    }
    @Override
    public Object execute(
        Map<UUID, Entry> entries, 
        BigInteger K, 
        ElgamalScheme elgamalScheme, 
        Map<String, Map<CertType, BigInteger>> userTransKeys){
            Entry storedEntry = entries.get(uuid);
            if(storedEntry == null)
                return 1;
            Clause storedClause = storedEntry.getClause();
            List<ClauseItem> storedItems = storedClause.getClause();
            List<ClauseItem> validItems = new ArrayList<>();
            // Match valid certs
            for(Certificate userCert: userCerts){
                CertType userType = userCert.getType();
                for(ClauseItem item: storedItems){
                    CertType storedType = item.getCertType();
                    if(userType.equals(storedType)){
                        ClauseItem clonedItem = new ClauseItem(storedType, item.getCipherPair(), item.getGroupCode());
                        validItems.add(clonedItem);
                    }
                }
            }
            if(userTransKeys.get(user) == null){
                System.out.println("[server] - user "+user+" is not registered");
                return 1;
            }
            
            // Pre-decrypt valid items for user
            for(ClauseItem item: validItems){
                CertType type = item.getCertType();
                BigInteger[] cipherpair = item.getCipherPair();
                BigInteger key = userTransKeys.get(user)
                    .get(type);
                item.setCipherPair(elgamalScheme.preDecrypt(key, cipherpair));
            }

            /**
             * Blind
             */

            int n, groupCode;
            Set<Integer> groups = new HashSet<>();

            // Count number of distinct bf's we need
            for(ClauseItem item: validItems){
                groupCode = item.getGroupCode();
                if(!groups.contains(groupCode))
                    groups.add(groupCode);
            }
            n = groups.size();

            BigInteger p = elgamalScheme.getP();
            BigInteger multiple = BigInteger.ONE;
            BigInteger val;
            List<BigInteger> blindingFactors = new ArrayList<>();
            if(n > 1){
                // Generate n - 1 random numbers and multiply them 
                for(int i=1; i<n; i++){
                    val = elgamalScheme.randomKey();
                    blindingFactors.add(val);
                    multiple = multiple.multiply(val).mod(p);
                }

                // Calc inverse
                BigInteger inverse = multiple.modInverse(p);
                blindingFactors.add(inverse);
            } else {
                blindingFactors.add(BigInteger.ONE);
            }
            
            // For each valid item, encrypt a blinding factor and multiply it
            // 1 bf per group code
            Map<Integer, BigInteger> bfMap = new HashMap<>();
            BigInteger bf, key;
            BigInteger[] bfPair, cipherpair;
            CertType type;
            for(ClauseItem item: validItems){
                groupCode = item.getGroupCode();
                type = item.getCertType();

                if(!bfMap.containsKey(groupCode))
                    bfMap.put(groupCode, blindingFactors.remove(0));
                bf = bfMap.get(groupCode);
                key = userTransKeys.get(user)
                    .get(type);

                bfPair = elgamalScheme.encrypt(K, bf);
                bfPair = elgamalScheme.preDecrypt(key, bfPair);

                cipherpair = item.getCipherPair();
                cipherpair = elgamalScheme.homomorphicMultiply(bfPair, cipherpair);
                item.setCipherPair(cipherpair);
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
    public Object execute(
        Map<UUID, Entry> entries, 
        BigInteger K, 
        ElgamalScheme elgamalScheme, 
        Map<String, Map<CertType, BigInteger>> userTransKeys){

            Map<CertType, BigInteger> userKeys = new HashMap<>();
            Map<CertType, BigInteger> transKeys = new HashMap<>();
            BigInteger p = elgamalScheme.getP();
            BigInteger userKey, transKey;

            if(userTransKeys.containsKey(name))
                userTransKeys.remove(name);
            for(CertType type:CertType.values()){
                userKey = elgamalScheme.randomKey();
                transKey = K.subtract(userKey).mod(p.subtract(new BigInteger("1")));
                userKeys.put(type, userKey);
                transKeys.put(type, transKey);
            }
            
            userTransKeys.put(name,transKeys);
            if(userTransKeys.get(name) == null)
                System.out.println("[server] - failed to add user "+name);
            return userKeys;
    }
}
/* Don't look at me */
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
