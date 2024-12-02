package client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import encryption.*;
import util.*;

public class PPClient {
    // Global vars
    private final static String CLIENT_STUB_INTERFACE = "Service";
	private final int AES_BITLEN = 127;
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
	private BigInteger symmetricKey;
	private SymScheme symScheme;
	

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
	 @SuppressWarnings("unchecked")
    private void run(String args[]){
		parseArgs(args);
        try{
			System.out.println("Connecting to " + serverIP + ":" + serverPort + "...");
			Registry registry = LocateRegistry.getRegistry(serverIP, serverPort);
			stub = (Service) registry.lookup(CLIENT_STUB_INTERFACE);

			Object result;
			switch(opType){
				case POST:
					System.out.println("Requesting Elgamal key scheme...");
					elgamalScheme = (ElgamalScheme)stub.requestScheme();
					System.out.println("Requesting Keys...");
					certKeys = (Map<CertType, BigInteger>)stub.requestKeys(userName);
					System.out.println("Getting Clause...");
					clause = clauseFromFile(cmd.getOptionValue("cl"));
					symmetricEncrypt();
					elgamalEncryptClause();
					System.out.println("Requesting POST operation...");
					result = stub.post(userName, clause, ciphertext, symScheme);
					System.out.println("Post successful! ID for posting is:");
					System.out.println((UUID)result);
					break;
				case GET:
					System.out.println("Requesting Elgamal key scheme...");
					elgamalScheme = (ElgamalScheme)stub.requestScheme();
					certKeys = (Map<CertType,BigInteger>)stub.requestKeys(userName);
					System.out.println("Requesting GET operation...");
					result = stub.get(userName, rid, certs);
					if(result.equals(1)){
						System.err.println("No item was found for uuid: "+rid);
						System.exit(1);
					}
					Entry entry = (Entry) result;
					symScheme = entry.getSymScheme();
					clause = entry.getClause();
					if(clause.getClause().size() == 0){
						System.err.println("You do not have any valid credentials for this posting.");
						System.exit(1);
					}
					ciphertext = entry.getCiphertext();
					elgamalDecryptClause();
					symmetricDecryptClause();
					plaintextToFile();
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
	 * Encrypt plaintext -> AES -> ciphertext
	 */
	private void symmetricEncrypt(){
		symScheme = new SymScheme(AES_BITLEN);
		ciphertext = symScheme.encrypt(plaintext, symmetricKey);
	}
	/**
	 * Decrypt clause into BigInt plaintext
	 */
	private void symmetricDecryptClause(){
		symmetricKey = BigInteger.ONE;
		BigInteger p = elgamalScheme.getP();
		Set<Integer> groupCodes = new HashSet<>();

		// Find symmetric key
		for(ClauseItem item: clause.getClause()){
			int groupCode = item.getGroupCode();
			BigInteger val;
			// Only process one item per group code
			if(!groupCodes.contains(groupCode)){
				groupCodes.add(groupCode);
				val = item.getCipherPair()[1];
				symmetricKey = symmetricKey.multiply(val).mod(p);
			}
		}
		symmetricKey = symmetricKey.mod((BigInteger.TWO).pow(AES_BITLEN));

		// Decrypt ciphertext
		plaintext = symScheme.decrypt(ciphertext, symmetricKey);
	}
	/**
	 * plaintextToFile: output the (already found) plaintext
	 */
	private void plaintextToFile(){
		String filename = rid + ".out";

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            ptToFileRecursion(writer, plaintext);
        } catch (IOException e) {
			System.err.println("Error writing plaintext to file "+filename);
            e.printStackTrace();
        }
		System.out.println("Successfully wrote output to file: "+filename);
	}
	private void ptToFileRecursion(BufferedWriter writer, BigInteger num){
		if(num.compareTo(BigInteger.ZERO) == 1){
			BigInteger[] divRem = num.divideAndRemainder(BigInteger.valueOf(256));
			ptToFileRecursion(writer, divRem[0]);
			try {
				writer.write((char)divRem[1].intValue());
			} catch (IOException e) {
				System.err.println("Failed writing char to plaintext file");
			}
		}
	}
	/**
	 * Decrypt the clause values with Elgamal
	 */
	private void elgamalDecryptClause(){
		BigInteger[] cipherpair;
		for(ClauseItem item: clause.getClause()){
			cipherpair = item.getCipherPair();
			item.setCipherPair(new BigInteger[]{
				BigInteger.ONE,
				elgamalScheme.decrypt(cipherpair)});
		}
	}
	/**
	 * Encrypt the clause values with Elgamal
	 * 
	 */
	private void elgamalEncryptClause(){
		for(ClauseItem item: clause.getClause()){
			CertType type = item.getCertType();
			BigInteger message = item.getCipherPair()[1];
			BigInteger key = certKeys.get(type);
			item.setCipherPair(elgamalScheme.encrypt(key, message));
		}
	}
    private static BigInteger bigIntFromFile(String path) {
        BigInteger binFile = BigInteger.ZERO;
        try (BufferedReader reader = 
			new BufferedReader(
			new FileReader(path))){  
				// Read char by char, convert to BigInt
				int c;
				while ((c = reader.read()) != -1) {
					binFile = binFile.shiftLeft(8);
					binFile = binFile.add(BigInteger.valueOf(c));
				}
        } catch (IOException e){
			System.err.println("Error reading file "+path);
			System.exit(1);
		}
        return binFile;
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
				if(certs.size() == 0)
					throw new IOException("You don't have any certifications");
				System.out.println("You have "+certs.size()+" certifications");
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
	private Clause clauseFromFile(String path) {
		System.out.println("Getting clause from file...");
        Clause cl = new Clause(new ArrayList<ClauseItem>());
		Map<Integer, ClauseGroup> groups = new HashMap<>();
		Set<CertType> certsUsed = new HashSet<CertType>();
		SecureRandom r = new SecureRandom();
        try (BufferedReader reader = 
			new BufferedReader(
			new FileReader(path))){  
				String line;
				//read first line to get rid of header
				reader.readLine();
				while ((line = reader.readLine()) != null) {
					if (line.equals("end")) {
						break;
					}
					String[] attributes = line.split(",");
					CertType cert = CertType.typeFromString(attributes[0].trim());
					certsUsed.add(cert);
					int groupCode = 0;
					try {
						groupCode = Integer.parseInt(attributes[1].trim());
					} catch (NumberFormatException e) {
						System.err.println("Invalid group number format: " +attributes[1].trim());
					}
					LogicOpType logicOperationType = LogicOpType.typeFromString(attributes[2].trim());
					int numberRequired = 0;
					if (logicOperationType == LogicOpType.XOFN) {
						numberRequired = Integer.parseInt(attributes[3].trim());
					}
					if (groups.containsKey(groupCode)) {
						ClauseGroup group = groups.get(groupCode);
						group.addCertToGroup(cert);
						if (logicOperationType == LogicOpType.XOFN) {
							group.incrementNumAvailable();
						}
					} else {
						int numberAvailable = 1;
						groups.put(groupCode, new ClauseGroup(logicOperationType, cert, numberRequired, numberAvailable));
					}
				}
        } catch (IOException e){
			System.err.println("Error reading file "+path);
			System.exit(1);
		}
		BigInteger symKey = BigInteger.ONE;
		Set<Integer> FinalGroupCodes = new HashSet<>();
		for (Integer key : groups.keySet()) {
			ClauseGroup group = groups.get(key);
			BigInteger subkey = group.processGroup(cl, FinalGroupCodes, elgamalScheme);
			if (subkey.equals(BigInteger.valueOf(-1))) {
				System.err.println("ERROR: Could not process group");
			}
			symKey = symKey.multiply(subkey).mod(elgamalScheme.getP());
			//System.out.println("Group: "+key+", ClauseGroup OP: "+group.getOperation()+", Certs: "+group.getCertList()+", Num Required (XOFN): "+group.getNumRequired());
		}
		for (CertType certification : CertType.values()) {
			if (!certsUsed.contains(certification)) {
				int code;
                do {
                    code = r.nextInt();
                } while (FinalGroupCodes.contains(code));
                // add group code to list of group codes so we don't use it again
                FinalGroupCodes.add(code);
				ClauseItem dontCare = new ClauseItem(certification, 
				new BigInteger[]{BigInteger.ONE, BigInteger.valueOf(1)},
				code);
				cl.addItem(dontCare);
			}
		}
		// mod to valid symmetric key length
		this.symmetricKey = symKey.mod((BigInteger.TWO).pow(AES_BITLEN));
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
				System.out.println("Getting Plaintext...");
				plaintext = bigIntFromFile(cmd.getOptionValue("pt"));
				System.out.println("Getting Username...");
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

		Option CREDENTIALS = new Option("ct", "cred", true, "Specify user credential file");
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
