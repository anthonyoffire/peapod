package server;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

import elgamal.ElgamalScheme;
import util.*;

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
    private String ciphertext;
    private String user;

    public PostJob(String user, Clause clause, String ciphertext){
        super();
        this.uuid = UUID.randomUUID();
        this.clause = clause;
        this.ciphertext = ciphertext;
        this.user = user;
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
            entries.put(uuid, new Entry(clause, ciphertext));
            return uuid;
    }
}
class GetEntryJob extends Job {
    private UUID uuid;
    private List<Certificate> userCerts;

    public GetEntryJob(UUID uuid, List<Certificate> certs){
        super();
        this.uuid = uuid;
        this.userCerts = certs;
    }
    @Override
    public Object execute(
        Map<UUID, Entry> entries, 
        BigInteger K, 
        ElgamalScheme elgamalScheme, 
        Map<String, Map<CertType, BigInteger>> userTransKeys){
            Entry entry = entries.get(uuid);

            return "GetJob Result";
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
