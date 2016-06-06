package server;

import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * Base class inherited by FileClient.java and GroupClient.java
 */
public abstract class Client
{
	protected Socket sock;                  // Used as endpoint for connection between two machines
	protected ObjectOutputStream output;    // The output stream for envelopes
	protected ObjectInputStream  input;     // The input stream for envelopes

    /**
     * This method connects to the specified server
     *
     * @param server The server
     * @param port The port
     *
     * @return true is successful, false otherwise
     */
	public boolean connect(final String server, final int port)
    {
        try
        {
            sock   = new Socket(server, port);
            output = new ObjectOutputStream(sock.getOutputStream());
            input  = new ObjectInputStream(sock.getInputStream());
        }
        catch (Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

        return isConnected();
	}

    /**
     * This method checks if there is a connection to a server
     *
     * @return true if there is a connection, false otherwise
     */
	public boolean isConnected()
    {
        if (sock == null || !sock.isConnected())
            return false;
        else
            return true;
    }


    /**
     * This method disconnects from any open connections by sending
     * a DISCONNECT envelope to the connected server
     */
	public void disconnect()
    {
		if (isConnected())
        {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
