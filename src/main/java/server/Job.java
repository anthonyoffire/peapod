package server;

import java.util.Map;
import java.util.Random;
import java.util.UUID;

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
    public Object execute(Map<UUID, Entry> entries){
        return null;
    };
}
class PostJob extends Job {
    private UUID uuid;
    private Clause clause;
    private String ciphertext;

    public PostJob(Clause clause, String ciphertext){
        super();
        this.uuid = UUID.randomUUID();
        this.clause = clause;
        this.ciphertext = ciphertext;
    }
    @Override
    public Object execute(Map<UUID, Entry> entries){
        entries.put(uuid, new Entry(clause, ciphertext));
        return uuid;
    }
}
class GetJob extends Job {

    public GetJob(){
        super();
    }
    @Override
    public Object execute(Map<UUID, Entry> entries){
        /* GET FUNCTIONALITY GOES HERE */
        return "GetJob Result";
    }
}
class DeleteJob extends Job {

    public DeleteJob(){
        super();
    }
    @Override
    public Object execute(Map<UUID, Entry> entries){
        /* DELETE FUNCTIONALITY GOES HERE */
        return "DeleteJob Result";
    }
}
