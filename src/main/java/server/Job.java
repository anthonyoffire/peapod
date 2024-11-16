package server;

import java.util.Random;

/* args must be the same for all execute methods. if you need a new arg, add to all of them */
public interface Job {
    public int getJid();
    public Object execute(/* args TBD */);
}
class PostJob implements Job {
    private int jid;

    public PostJob(){
        this.jid = new Random().nextInt(1000000);
    }
    public int getJid() {
        return jid;
    }
    @Override
    public Object execute(/* args TBD */){
        /* POST FUNCTIONALITY GOES HERE */
        return "PostJob Result";
    }
}
class GetJob implements Job {
    private int jid;

    public GetJob(){
        this.jid = new Random().nextInt(1000000);
    }
    public int getJid() {
        return jid;
    }
    @Override
    public Object execute(/* args TBD */){
        /* GET FUNCTIONALITY GOES HERE */
        return "GetJob Result";
    }
}
class DeleteJob implements Job {
    private int jid;

    public DeleteJob(){
        this.jid = new Random().nextInt(1000000);
    }
    public int getJid() {
        return jid;
    }
    @Override
    public Object execute(/* args TBD */){
        /* DELETE FUNCTIONALITY GOES HERE */
        return "DeleteJob Result";
    }
}
