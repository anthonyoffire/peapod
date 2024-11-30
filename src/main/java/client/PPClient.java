package client;

import org.apache.commons.cli.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import util.*;
import elgamal.ElgamalScheme;

public class PPClient {
    // Global vars
    private final static String CLIENT_STUB_INTERFACE = "Service";
    private Service stub;
    private Options options;
    private CommandLine cmd;
    private OpType opType;
    private static String serverIP;
    private int serverPort;

	private UUID rid;
	private List<Certificate> certs;
	private BigInteger ciphertext, plaintext;
	private Clause clause;
	private String userName;
    private Map<CertType, BigInteger> certKeys;
	private ElgamalScheme elgamalScheme;

    public static void main(String[] args) {
		System.setProperty("javax.net.ssl.trustStore", "src/main/resources/server.truststore");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
        System.setProperty("java.security.policy", "src/main/resources/mysecurity.policy");
        PPClient client = new PPClient();
        
        client.run(args);
    }
    /**
     * run: send post/req to server
     */
    private void run(String args[]){
		parseArgs(args);
        try{
			System.out.println("Connecting to " + serverIP + ":" + serverPort + "...");
			Registry registry = LocateRegistry.getRegistry(serverIP, serverPort);
			stub = (Service) registry.lookup(CLIENT_STUB_INTERFACE);

			Object result;
			switch(opType){
				case POST:
					/**
					 * Location for symmetric encryption of plaintext
					 */
					System.out.println("Requesting Elgamal key scheme...");
					elgamalScheme = stub.requestScheme();
					certKeys = stub.requestKeys(userName);
					elgamalEncryptClause();
					System.out.println("Requesting POST operation...");
					result = stub.post(userName, clause, ciphertext);
					System.out.println("Post successful! ID for posting is:");
					System.out.println(result);
					break;
				case GET:
					System.out.println("Requesting Elgamal key scheme...");
					elgamalScheme = stub.requestScheme();
					certKeys = stub.requestKeys(userName);
					System.out.println("Requesting GET operation...");
					result = stub.get(userName, rid, certs);
					System.out.println(result);
					break;
				case DELETE:
					System.out.println("Requesting DELETE operation...");
					result = stub.delete();
					System.out.println(result);
					break;
			}
		} catch (RemoteException | NotBoundException e) {
			System.err.println(e);
		}
	
	}
	/**
	 * Encrypt the clause values with Elgamal
	 * @param es
	 */
	private void elgamalEncryptClause(){
		for(ClauseItem item: clause.getClause()){
			CertType type = item.getCertType();
			BigInteger message = item.getVal();
			BigInteger key = certKeys.get(type);
			item.setVal(elgamalScheme.encrypt(key, message));
		}
	}
    private static String strFromFile(String path) {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = 
			new BufferedReader(
			new FileReader(path))){  
 
				String line;
				while ((line = reader.readLine()) != null) {
					content.append(line).append(System.lineSeparator());
				}
        } catch (IOException e){
			System.err.println("Error reading file "+path);
			System.exit(1);
		}
        return content.toString();
    }
	private static ArrayList<Certificate> certsFromFile(String path){
		ArrayList<Certificate> certs = new ArrayList<>();
        try (BufferedReader reader = 
			new BufferedReader(
			new FileReader(path))){  
 
				String line;
				while ((line = reader.readLine()) != null) {
					String tokens[] = line.split(" ");
					for(String token : tokens){
						CertType type = CertType.typeFromString(token);
						if(type != null)
							certs.add(new Certificate(type));
					}
				}
        } catch (IOException e){
			System.err.println("Error reading file "+path);
			System.exit(1);
		}
        return certs;
	}
	/**
	 * Parse clause file and set clause values
	 * @param path
	 * @return Clause 
	 */
	private static Clause clauseFromFile(String path) {
        Clause cl = new Clause(new ArrayList<ClauseItem>());
        try (BufferedReader reader = 
			new BufferedReader(
			new FileReader(path))){  
 
				String line;
				while ((line = reader.readLine()) != null) {
					// DAN parse clause file and set cl here
				}
        } catch (IOException e){
			System.err.println("Error reading file "+path);
			System.exit(1);
		}
        return cl;
    }
    /**
     * printUsage: Something went wrong. Print usage, message, and quit.
     * @param message the error message to print
     */
    private void printUsage(String message){
        new HelpFormatter().printHelp(100, "java client.PPClient ","\n", options, "\n" + message, true);
		System.exit(1);
    }
    /**
	 * parseArgs: Get and set the run options
	 * 
	 * @param args the arguments
	 */
	private void parseArgs(String args[]) {
		try {
			options = setOptions();
			cmd = new DefaultParser().parse(options, args);
            serverIP = cmd.getOptionValue("ip");
            serverPort = Integer.parseInt(cmd.getOptionValue("port"));
			if(serverIP == null)
				throw new ParseException("Must specify server IP");

			if(cmd.hasOption('p')){
				opType  = OpType.POST;
				if(!cmd.hasOption("pt") || !cmd.hasOption("cl") || !cmd.hasOption("u"))
					throw new ParseException("Must specify username, clause and plaintext files");
				clause = clauseFromFile(cmd.getOptionValue("cl"));
				plaintext = new BigInteger(strFromFile(cmd.getOptionValue("pt")));
				userName = cmd.getOptionValue("u");
				
			}
			else if (cmd.hasOption('g')){
				opType = OpType.GET;
				if(!cmd.hasOption("id") || !cmd.hasOption("ct") || !cmd.hasOption("u"))
					throw new ParseException("Must specify request ID and certificate path");
				
				rid = UUID.fromString(cmd.getOptionValue("id"));
				certs = certsFromFile(cmd.getOptionValue("ct"));
				userName = cmd.getOptionValue("u");
			}
			else if (cmd.hasOption('d'))
				opType = OpType.DELETE;

		} catch (ParseException e) {
			printUsage(e.getMessage());
		} catch (NumberFormatException e) {
			System.err.println("Invalid port");
			printUsage(e.getMessage());
		}
	}
    /**
	 * setOptions: Configure possible arguments for running this client
	 * 
	 * @return The configured Options object
	 */
	private static Options setOptions() {
		Options options = new Options();

        Option IP = new Option("ip", "ip_add", true, "The server's IP");
        IP.setArgName("ipaddress");
        options.addOption(IP);

		Option PORT = new Option("port", "portnum", true, "The server's port");
		PORT.setArgName("portnum");
		options.addOption(PORT);
		
		OptionGroup OP_TYPE = new OptionGroup();

		Option POST = new Option("p", "post", false, "Post entry from server");
		POST.setArgName("post");
		OP_TYPE.addOption(POST);

		Option GET = new Option("g", "get", false, "Get entry from server");
		GET.setArgName("get");
		OP_TYPE.addOption(GET);

		Option DELETE = new Option("d", "delete", false, "Delete entry from server");
		DELETE.setArgName("delete");
		OP_TYPE.addOption(DELETE);

		Option CREDENTIALS = new Option("c", "cred", true, "Specify user credential file");
		CREDENTIALS.setArgName("cred");
		options.addOption(CREDENTIALS);

		Option REQ_ID = new Option("id", "request_id", true, "Target ID for request to server");
		REQ_ID.setArgName("reqID");
		options.addOption(REQ_ID);

		Option PLAINTEXT = new Option("pt", "plaintext", true, "Plaintext to encrypt for post");
		REQ_ID.setArgName("plaintext");
		options.addOption(PLAINTEXT);

		Option CLAUSE = new Option("cl", "clause", true, "Clause to post");
		REQ_ID.setArgName("clause");
		options.addOption(CLAUSE);

		Option USERNAME = new Option("u", "user", true, "Username");
		REQ_ID.setArgName("username");
		options.addOption(USERNAME);

		options.addOptionGroup(OP_TYPE);

		return options;
	}
}
