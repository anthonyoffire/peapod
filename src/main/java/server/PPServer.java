package server;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RMISocketFactory;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

import org.apache.commons.cli.*;

import elgamal.ElgamalScheme;
import util.*;

/**
 *  PeaPod Server
 */
public class PPServer implements Service {
	//Global vars
	private boolean verbose;
    private Options options;
	private int port;
	private final static String SERVER_NAME = "Service";
	private final static int ELGAMAL_BIT_LENGTH = 1024;

	private Object resultLock = new Object();
	
	private ConcurrentLinkedQueue<Job> jobQueue = new ConcurrentLinkedQueue<>();
	private ConcurrentHashMap<Integer, Object> jobResults = new ConcurrentHashMap<>();
	private Map<UUID, Entry> entries = new HashMap<>();
	private ElgamalScheme elgamalScheme;
	private Map<String, Map<CertType, BigInteger>> userTransKeys = new HashMap<>();
	private BigInteger K;

	public PPServer() throws RemoteException{
		super();
	}
    public static void main(String[] args) {
		System.setProperty("javax.net.ssl.keyStore", "src/main/resources/server.keystore");
		System.setProperty("javax.net.ssl.keyStorePassword", "password");
		System.setProperty("java.security.policy", "src/main/resources/mysecurity.policy");
		System.setProperty("javax.net.ssl.trustStore", "src/main/resources/server.truststore");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
        try{
			PPServer server = new PPServer();
			server.parseArgs(args);
			server.bindServer();
			server.elgamalScheme = new ElgamalScheme(ELGAMAL_BIT_LENGTH);
			server.K = server.elgamalScheme.randomKey();
			server.handleJobs();
		} catch (Exception e){
			System.err.println(e.getMessage());
			System.exit(1);
		}
    }
	/**
	 * handleJobs: loop forever handling jobs. Should only need to modify job.execute args
	 * 			   jobs are added to queue via RMI calls in other threads.
	 */
	private void handleJobs(){
		for (;;) {
			// Wait for jobs
			while (jobQueue.isEmpty()) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
				}
			}
			// Handle a job
			Job job = jobQueue.poll();
			Object result = job.execute(entries, K, elgamalScheme, userTransKeys);
			
			jobResults.put(job.getJid(), result);
			
			// Notify any awaiting RMI calls
			synchronized (resultLock) {
				resultLock.notify();
			}
		}
	}
	/**
	 * Here are the methods we can call with the client. When changing args or return type, or
	 * adding more methods, also change them in Service.java
	 */
	@Override
	public synchronized UUID post(String name, Clause clause, BigInteger ciphertext) throws RemoteException {
		Job job = new PostJob(name, clause, ciphertext);
		int jid = job.getJid();
		jobQueue.add(job);
		waitForJob(jid);
		return (UUID)getResult(jid);
	}
	@Override
	public synchronized Entry get(String name, UUID id, List<Certificate> certs) throws RemoteException {
		Job job = new GetEntryJob(name, id, certs);
		int jid = job.getJid();
		jobQueue.add(job);
		waitForJob(jid);
		return (Entry)getResult(jid);
	}
	@Override
	public synchronized Object delete() throws RemoteException {
		Job job = new DeleteJob();
		int jid = job.getJid();
		jobQueue.add(job);
		waitForJob(jid);
		return getResult(jid);
	}
	@Override
	@SuppressWarnings("unchecked")
	public synchronized Map<CertType, BigInteger> requestKeys(String user) throws RemoteException {
		Job job = new GetKeysJob(user);
		int jid = job.getJid();
		jobQueue.add(job);
		waitForJob(jid);
		return (Map<CertType, BigInteger>)getResult(jid);
		
	}
	@Override
	public synchronized ElgamalScheme requestScheme() throws RemoteException {
		return elgamalScheme;
	}
	/**
	 * waitForJob: blocks until a job with jid is finished
	 * @param jid the job id
	 */
	private void waitForJob(int jid) {
		while (jobResults.get(jid) == null) {
			try {
				synchronized (resultLock) {
					resultLock.wait();
				}
			} catch (InterruptedException e) {
				System.err.println("[server] - Thread interrupted while waiting for job result");
			}
		}
	}
	/**
	 * getResult: retrieves a job result
	 * @param jid the job id
	 * @return the job result
	 */
	private Object getResult(int jid) {
		return jobResults.remove(jid);
	}
	/**
	 * bindServer: Bind server to RMI registry
	 */
	private void bindServer() {
		try {
			RMIClientSocketFactory rmiClientSocketFactory = new SslRMIClientSocketFactory();
			RMIServerSocketFactory rmiServerSocketFactory = new SslRMIServerSocketFactory();
			RMISocketFactory.setSocketFactory(new SocketFactory());
			Service authServer = (Service) UnicastRemoteObject.exportObject(this, 0, rmiClientSocketFactory,
					rmiServerSocketFactory);
			Registry registry = LocateRegistry.getRegistry(port);
			registry.rebind(SERVER_NAME, authServer);
			System.out.println("[server] -  server is bound, using port " + port);
		} catch (Exception e) {
			System.err.println("[server] - Bind failed!!! Server shutting down.");
			System.err.println(e.getMessage());
			System.exit(1);
		}
	}
	/**
	 * printUsage: Invalid options were entered. Print correct usage and exit with
	 * status 1.
	 * 
	 * @param e The error message
	 */
	private void printUsage(String e) {
		new HelpFormatter().printHelp(100, "java ", "\n", options, "\n" + e, true);
		System.exit(1);
	}
	/**
	 * parseArgs: Get and set the run options
	 * 
	 * @param args the arguments
	 */
	private void parseArgs(String args[]) {
		CommandLine cmd;
		try {
			options = setOptions();
			cmd = new DefaultParser().parse(options, args);
            if(!cmd.hasOption("port"))
				throw new ParseException("Tell me the port number");
			port = Integer.parseInt(cmd.getOptionValue("port"));
			verbose = cmd.hasOption('v');

		} catch (ParseException e) {
			printUsage(e.getMessage());
			System.exit(1);
		} catch (NumberFormatException e) {
			System.err.println("Invalid port");
			printUsage(e.getMessage());
			System.exit(1);
		}
	}
    /**
	 * setOptions: Configure possible arguments for running this server
	 * 
	 * @return The configured Options object
	 */
	private static Options setOptions() {
		Options options = new Options();

		Option PORT = new Option("port", "portnum", true, "The server's port");
		PORT.setArgName("portnum");
		options.addOption(PORT);

		Option VERBOSE = new Option("v", "verbose", false, "Print detailed messages on operations");
		VERBOSE.setArgName("verbose");
		options.addOption(VERBOSE);

		return options;
	}
}
