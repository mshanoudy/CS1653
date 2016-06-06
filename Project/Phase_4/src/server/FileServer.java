package server;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;

/**
 * FileServer loads files from FileList.bin. Stores files in shared_files directory.
 */
public class FileServer extends Server
{
    public static final int SERVER_PORT = 4321;
    public static FileList  fileList; // The list of files on the server
    public PublicKey  publicKey;      // The public key of this server
    public PrivateKey privateKey;     // The private key of this server

    /**
     * Default constructor.
     * Uses default port and base constructor @see Server#Server(int _SERVER_PORT, String _serverName)
     */
    public FileServer()
    {
        super(SERVER_PORT, "FilePile");
    }

    /**
     * Constructor which accepts a port number.
     * Uses base constructor @see Server#Server(int _SERVER_PORT, String _serverName)
     * @param _port The port number
     */
    public FileServer(int _port)
    {
        super(_port, "FilePile");
    }

    /**
     * Main method of server
     */
    public void start()
    {
        String fileFile = "FileList.bin";    // The file holding the FileList
        String keyFile  = "FileKeyPair.bin"; // The file holding the KeyPair
        ObjectInputStream fileStream;        // The InputStream for the fileFile
        ObjectInputStream keyStream;         // The InputStream for the keyFile
        FileInputStream   fis;               // The FileInputStream for all ObjectInputStreams
        KeyPair keyPair;                     // The KeyPair for this server

        // This runs a thread that saves the list on program exit
        Runtime runtime   = Runtime.getRuntime();
        Thread  catchExit = new Thread(new ShutDownListenerFS());
        runtime.addShutdownHook(catchExit);

        try
        {// Open user file to get user list
            // Open and read FileList.bin
            fis        = new FileInputStream(fileFile);
            fileStream = new ObjectInputStream(fis);
            fileList   = (FileList)fileStream.readObject();
            // Open and read FileKeyPair.bin
            fis        = new FileInputStream(keyFile);
            keyStream  = new ObjectInputStream(fis);
            keyPair    = (KeyPair)keyStream.readObject();
            publicKey  = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        }
        catch (FileNotFoundException e)
        {// fileFile.bin does not exist
            System.out.println("FileList or KeyPair Does Not Exist. Creating new FileList...");
            fileList  = new FileList();

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
            }
            catch (NoSuchAlgorithmException | IOException e1)
            {
                e1.printStackTrace();
            }
        }
        catch (IOException | ClassNotFoundException e)
        {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        }

        // Create shared_files directory
        File file = new File("shared_files");
        if (file.mkdir())
            System.out.println("Created new shared_files directory");
        else if (file.exists())
            System.out.println("Found shared_files directory");
        else
            System.out.println("Error creating shared_files directory");

        // Autosave Daemon. Saves lists every 5 minutes
        AutoSaveFS aSave = new AutoSaveFS();
        aSave.setDaemon(true);
        aSave.start();

        boolean running = true;

        try
        {// Launch FileThread
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock;
            Thread thread;

            while (running)
            {
                sock   = serverSock.accept();
                thread = new FileThread(sock, this);
                thread.start();
            }

            System.out.printf("%s shut down\n", this.getClass().getName());
        }
        catch (Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

/**
 * This thread saves user and group lists
 */
class ShutDownListenerFS implements Runnable
{
    public void run()
    {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;

        try
        {
            outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
            outStream.writeObject(FileServer.fileList);
        }
        catch(Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

/**
 * This thread autosaves FileList every 5 min
 */
class AutoSaveFS extends Thread
{
    public void run()
    {
        do
        {
            try
            {// Save file list every 2 minutes
                Thread.sleep(120000);
                System.out.println("Autosave file list...");
                ObjectOutputStream outStream;
                try
                {
                    outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
                    outStream.writeObject(FileServer.fileList);
                }
                catch (Exception e)
                {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }
            }
            catch (Exception e)
            {
                System.out.println("Autosave Interrupted");
            }
        } while (true);
    }
}
