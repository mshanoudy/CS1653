package server;

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.security.*;
import java.util.*;

/**
 * GroupServer loads the users from UserList.bin and the groups from GroupList.bin,
 * If either UserList.bin or GroupList.bin does not exist, it creates a new UserList and makes the user ADMIN
 * and then creates a new GroupList and adds ADMIN to the list with the user as owner.
 * On exist, the server saves the UserList and GroupList to their respective files.
 */
public class GroupServer extends Server
{
	public static final int SERVER_PORT = 8765;
	public UserList   userList;   // The list of users on this server
    public GroupList  groupList;  // The list of groups on this server
    public PublicKey  publicKey;  // The public key of the server
    public PrivateKey privateKey; // The private key of the server

    /**
     * Default constructor.
     * Uses default port and base constructor @see Server#Server(int _SERVER_PORT, String _serverName)
     */
	public GroupServer()
    {
		super(SERVER_PORT, "ALPHA");
	}

    /**
     * Constructor which accepts a port number.
     * Uses base constructor @see Server#Server(int _SERVER_PORT, String _serverName)
     *
     * @param _port The port
     */
	public GroupServer(int _port)
    {
		super(_port, "ALPHA");
	}

    /**
     * Main server method
     */
	public void start()
    {// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		String  userFile  = "UserList.bin";         // The file holding the UserList
        String  groupFile = "GroupList.bin";        // The file holding the GroupList
        String  keyFile   = "GroupKeyPair.bin";     // The file holding the KeyPair
		Scanner console   = new Scanner(System.in); // The scanner for console input
		ObjectInputStream userStream;               // The InputStream for the userFile
		ObjectInputStream groupStream;              // The InputStream for the groupFile
        ObjectInputStream keyStream;                // The InputStream for the keyFile
        FileInputStream   fis;                      // The FileInputStream for all ObjectInputStreams
        KeyPair keyPair;                            // The KeyPair for this server

		// This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		try
		{// Open user and group files to get lists
            // Open user file
			fis         = new FileInputStream(userFile);
			userStream  = new ObjectInputStream(fis);
			userList    = (UserList)userStream.readObject();
            // Open group file
            fis         = new FileInputStream(groupFile);
            groupStream = new ObjectInputStream(fis);
            groupList   = (GroupList)groupStream.readObject();
            // Open key file
            fis         = new FileInputStream(keyFile);
            keyStream   = new ObjectInputStream(fis);
            keyPair     = (KeyPair)keyStream.readObject();
            publicKey   = keyPair.getPublic();
            privateKey  = keyPair.getPrivate();
		}
		catch (FileNotFoundException e)
		{
			System.out.println("UserList or GroupList File Does Not Exist. Creating new UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
            System.out.print("Enter your password: ");
            String password = console.next();
            System.out.println();

			// Create a new userList, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username, password);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");

            System.out.println("Creating new GroupList...");
            System.out.println("No groups currently exist. Your account will be added to the ADMIN group.");

            // Create a new groupList, create ADMIN group, add current user to ADMIN group as owner
            groupList = new GroupList();
            groupList.addGroup("ADMIN");
            groupList.setOwner(username, "ADMIN");

            System.out.println("Generating new KeyPair...");
            try
            {// Create a new KeyPair
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048); // Initialize key size to 2048-bits
                keyPair    = keyPairGenerator.generateKeyPair();
                publicKey  = keyPair.getPublic();
                System.out.println(publicKey.toString());
                privateKey = keyPair.getPrivate();
                System.out.println(privateKey.toString());

                // Save to file
                ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(keyFile));
                outputStream.writeObject(keyPair);
                outputStream.flush();
                outputStream.close();
            }
            catch (NoSuchAlgorithmException | IOException e1)
            {
                e1.printStackTrace();
            }
        }
		catch (IOException | ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList or GroupList file");
			System.exit(-1);
		}

        // Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		// This block listens for connections and creates threads on new connections
		try
		{
			final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

			Socket      sock;
			GroupThread thread;

			while (true)
			{// Start GroupThread
				sock   = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		}
		catch (Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

/**
 * This thread saves the user and group lists
 */
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs)
    {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
            outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
            outStream.writeObject(my_gs.groupList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

/**
 * This thread autosaves the user and group lists every 5 min
 */
class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs)
    {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{// Save group and user lists every 2 minutes
				Thread.sleep(120000);
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
                    outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
                    outStream.writeObject(my_gs.groupList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
            }
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		} while (true);
	}
}
