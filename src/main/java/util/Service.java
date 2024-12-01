package util;

import java.math.BigInteger;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import encryption.*;

/**
 * Service: Interface to define RMI methods
 *
 */
public interface Service extends Remote {
	public UUID post(String name, Clause clause, BigInteger ciphertext, SymScheme symScheme) throws RemoteException;

	public Entry get(String name, UUID id, List<Certificate> certs) throws RemoteException;

	public Object delete(/* args TBD */) throws RemoteException;

	public Map<CertType, BigInteger> requestKeys(String user) throws RemoteException;

	public ElgamalScheme requestScheme() throws RemoteException;
	
}