package util;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;
import java.util.UUID;

/**
 * Service: Interface to define RMI methods
 *
 */
public interface Service extends Remote {
	public Object post(Clause clause, String ciphertext) throws RemoteException;

	public Object get(UUID id, List<Certificate> certs) throws RemoteException;

	public Object delete(/* args TBD */) throws RemoteException;
	
}