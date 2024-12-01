package util;

import java.math.BigInteger;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;
import java.util.UUID;

import encryption.*;

/**
 * Service: Interface to define RMI methods
 *
 */
public interface Service extends Remote {
	public Object post(String name, Clause clause, BigInteger ciphertext, SymScheme symScheme) throws RemoteException;

	public Object get(String name, UUID id, List<Certificate> certs) throws RemoteException;

	public Object delete(/* args TBD */) throws RemoteException;

	public Object requestKeys(String user) throws RemoteException;

	public Object requestScheme() throws RemoteException;
	
}