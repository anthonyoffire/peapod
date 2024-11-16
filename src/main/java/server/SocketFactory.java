package server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.rmi.server.RMISocketFactory;

public class SocketFactory extends RMISocketFactory{
    private static final int TIMEOUT = 1000;
        
        private final int timeout;
        
        SocketFactory() {
            this.timeout = TIMEOUT;
        }

        SocketFactory(int timeout) {
            this.timeout = timeout;
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
        	Socket socket = new TimeoutSocket(host, port);
            socket.setSoTimeout(timeout);
            socket.setSoLinger(false, 0);
            return socket;
        }

        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port);
        }
        
        class TimeoutSocket extends Socket {
            public TimeoutSocket(String host, int port) throws IOException {
                super(host, port);
            }

            @Override
            public void connect(SocketAddress endpoint) throws IOException {
                connect(endpoint, TIMEOUT);
            }
        }
}
