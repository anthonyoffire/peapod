package server;

import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RMISocketFactory;
import java.rmi.server.UnicastRemoteObject;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

import org.apache.commons.cli.*;

import util.*;

public class PPServer implements Service {
	//Global vars
	private String thisHost;
	private boolean verbose;
    private Options options;
	private int port;

	private Object resultLock = new Object();
	
	private ConcurrentLinkedQueue<Job> jobQueue = new ConcurrentLinkedQueue<>();
	private ConcurrentHashMap<Integer, Object> jobResults = new ConcurrentHashMap<>();

	private static final String SERVER_NAME = "Service";

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
			server.thisHost = InetAddress.getLocalHost().getHostAddress();
			server.parseArgs(args);
			server.bindServer();
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
			Object result = job.execute(/* args TBD */);
			
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
	public synchronized Object post() throws RemoteException {
		Job job = new PostJob();
		int jid = job.getJid();
		jobQueue.add(job);
		waitForJob(jid);
		return getResult(jid);
	}
	@Override
	public synchronized Object get() throws RemoteException {
		Job job = new GetJob();
		int jid = job.getJid();
		jobQueue.add(job);
		waitForJob(jid);
		return getResult(jid);
	}
	@Override
	public synchronized Object delete() throws RemoteException {
		Job job = new DeleteJob();
		int jid = job.getJid();
		jobQueue.add(job);
		waitForJob(jid);
		return getResult(jid);
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
