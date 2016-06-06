package server;

import java.net.Socket;

/**
 * Base class for FileServer.java and GroupServer.java
 */
public abstract class Server
{
	protected int port;
	public String name;
	abstract void start();
	
	public Server(int _SERVER_PORT, String _serverName)
    {
		port = _SERVER_PORT;
		name = _serverName; 
	}

	public int getPort()
    {
		return port;
	}
	
	public String getName()
    {
		return name;
	}
}
