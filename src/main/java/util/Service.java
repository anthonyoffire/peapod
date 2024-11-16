package util;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * Service: Interface to define RMI methods
 *
 */
public interface Service extends Remote {
	public Object post(/* args TBD */) throws RemoteException;

	public Object get(/* args TBD */) throws RemoteException;

	public Object delete(/* args TBD */) throws RemoteException;
	
}