package client;

import org.apache.commons.cli.*;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import util.*;

public class PPClient {
    // Global vars
    private final static String CLIENT_STUB_INTERFACE = "Service";
    private Service stub;
    private Options options;
    private CommandLine cmd;
    private OpType opType;
    private static String serverIP;
    private int serverPort;

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
					System.out.println("Requesting POST operation...");
					result = stub.post();
					System.out.println(result);
					break;
				case GET:
					System.out.println("Requesting GET operation...");
					result = stub.get();
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
     * printUsage: Something went wrong. Print usage, message, and quit.
     * @param message the error message to print
     */
    private void printUsage(String message){
        new HelpFormatter().printHelp(100, "java client.IdClient ","\n", options, "\n" + message, true);
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

			if(cmd.hasOption('p'))
				opType  = OpType.POST;
			else if (cmd.hasOption('g'))
				opType = OpType.GET;
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

		Option REQ_ID = new Option("rid", "request_id", true, "Target ID for request to server");
		REQ_ID.setArgName("reqID");
		options.addOption(REQ_ID);

		options.addOptionGroup(OP_TYPE);

		return options;
	}
}
