package server;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import java.lang.Thread;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.io.*;

/**
 * FileServer's worker thread
 * Handles the business of upload, download, and removing files for clients with valid tokens
 */
public class FileThread extends Thread
{
    private final Socket     socket;           // The socket passed from FileServer
    private       FileServer my_fs;            // The FileServer

    /**
     * Constructor which accepts the socket passed from FileServer
     * @param _socket The socket
     */
    public FileThread(Socket _socket, FileServer _fs)
    {
        socket = _socket;
        my_fs  = _fs;
    }

    /**
     * Method that runs the thread that includes handlers for upload, download, and file removal
     */
    public void run()
    {
        boolean proceed = true;

        try
        {// Establish connection and input/output streams
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " ***");
            final ObjectInputStream  input  = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

            /* HANDSHAKE PROTOCOL */
            System.out.println("Handshake with FileClient started");

            // Set provider as BouncyCastle
            Security.addProvider(new BouncyCastleProvider());

            // Set RSA cipher
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.DECRYPT_MODE, my_fs.privateKey);

            // Send Public Key to client
            output.writeObject(my_fs.publicKey);

            // Send fileServerID to client
            output.writeObject((my_fs.getName() + my_fs.getPort()));

            // Needed to convert from byte arrays
            CryptoTools ct = new CryptoTools();

            // Set up CryptoTools
            ct = new CryptoTools(new BigInteger(cipher.doFinal((byte[])input.readObject())).intValue(),// N
                    (SecretKey)ct.fromByteArray(cipher.doFinal((byte[])input.readObject())),           // KS
                     cipher.doFinal((byte[])input.readObject()),                                       // IV
                    (SecretKey)ct.fromByteArray(cipher.doFinal((byte[])input.readObject())));          // KH
            PublicKey  KGS = (PublicKey)input.readObject();                                            // KGS
            BigInteger RC  = (BigInteger)ct.fromByteArray(cipher.doFinal((byte[])input.readObject())); // RC

            // RC + 1
            RC = new BigInteger(String.valueOf(RC.intValue() + 1));

            // Encrypt and send back challenge response using KS
            ct.incrementN();
            Envelope envelope = new Envelope("RC+1");
            envelope.addObject(ct.getN()); // Add N
            envelope.addObject(RC);        // Add RC
            output.writeObject(ct.encrypt(envelope));   // Send cipher text
            output.writeObject(ct.getDigest(envelope)); // Send message digest

            System.out.println("Handshake with FileClient complete");
            do
            {// Listen for messages from client
                Envelope e       = (Envelope)ct.decrypt((byte[])input.readObject());
                byte[]   digest  = (byte[])input.readObject();
                System.out.println("Request received: " + e.getMessage());
                // Verify message integrity
                if (ct.verifyMessage(e, digest))
                    ct.incrementN();
                else
                {// Verification failed
                    System.out.println("Message Verification Failed");
                    socket.close();  // Close the socket
                    proceed = false; // End this communication loop
                }

                Envelope response = null;  // Server response

                /* Client wants to list files the requester can see */
                if (e.getMessage().equals("LFILES"))
                {
                    // Check to make sure parameter is passed and != null
                    if (e.getObjContents().size() < 2 && e.getObjContents().get(1) == null)
                    {
                        ct.incrementN();
                        response = new Envelope("FAIL-BADCONTENTS");
                        response.addObject(ct.getN());
                    }

                    else
                    {// Extract token
                        SignedObject so = (SignedObject)e.getObjContents().get(1);
                        UserToken yourToken = verifyToken(so, KGS);
                        // list to hold the files the requester can see
                        List<String> list = new ArrayList<>();
                        // Iterate over each file and check against requester groups
                        // TODO: probably a better way to do this and need to account for ADMIN group
                        for (int i = 0; i < FileServer.fileList.getFiles().size(); i++)
                            for (int j = 0; j < yourToken.getGroups().size(); j++)
                                if (FileServer.fileList.getFiles().get(i).getGroup().equals(yourToken.getGroups().get(j)))
                                    list.add(FileServer.fileList.getFiles().get(i).getPath());
                        // If list is created, change response to OK
                        ct.incrementN();
                        response = new Envelope("OK");
                        response.addObject(ct.getN()); // Add N
                        response.addObject(list);      // Add the list
                    }
                    // Send response
                    output.writeObject(ct.encrypt(response));
                }
                /* Client wants to upload file */
                else if (e.getMessage().equals("UPLOADF"))
                {
                    // Check to make sure all parameters are passed
                    if (e.getObjContents().size() < 6)
                    {
                        ct.incrementN();
                        response = new Envelope("FAIL-BADCONTENTS");
                        response.addObject(ct.getN());
                    }
                    else
                    {// Check to make sure parameters != null
                        if (e.getObjContents().get(1) == null)
                        {// Filename missing
                            ct.incrementN();
                            response = new Envelope("FAIL-BADPATH");
                            response.addObject(ct.getN());
                        }
                        else if (e.getObjContents().get(2) == null)
                        {// Group name missing
                            ct.incrementN();
                            response = new Envelope("FAIL-BADGROUP");
                            response.addObject(ct.getN());
                        }
                        else if (e.getObjContents().get(3) == null)
                        {// Group key missing
                            ct.incrementN();
                            response = new Envelope("FAIL-BADKEY");
                            response.addObject(ct.getN());
                        }
                        else if (e.getObjContents().get(4) == null)
                        {// IV missing
                            ct.incrementN();
                            response = new Envelope("FAIL-BADIV");
                            response.addObject(ct.getN());
                        }
                        else if (e.getObjContents().get(5) == null)
                        {// Token missing
                            ct.incrementN();
                            response = new Envelope("FAIL-BADTOKEN");
                            response.addObject(ct.getN());
                        }
                        else
                        {
                            String       remotePath  = (String)e.getObjContents().get(1);       // Extract filename
                            String       group       = (String)e.getObjContents().get(2);       // Extract group name
                            SecretKey    groupKey    = (SecretKey)e.getObjContents().get(3);    // Extract group key
                            byte[]       IV          = (byte[])e.getObjContents().get(4);       // Extract group IV
                            SignedObject so          = (SignedObject)e.getObjContents().get(5); // Extract SignedObject
                            UserToken yourToken = verifyToken(so, KGS); // Extract requester token

                            if (FileServer.fileList.checkFile(remotePath))
                            {// File exists
                                System.out.printf("Error: file already exists at %s\n", remotePath);
                                ct.incrementN();
                                response = new Envelope("FAIL-FILEEXISTS");
                                response.addObject(ct.getN());
                            }
                            else if (!yourToken.getGroups().contains(group))
                            {// Not part of group
                                System.out.printf("Error: user missing valid token for group %s\n", group);
                                ct.incrementN();
                                response = new Envelope("FAIL-UNAUTHORIZED");
                                response.addObject(ct.getN());
                            }
                            else
                            {
                                // Create group directory
                                File file = new File("shared_files/" + group);
                                if (file.mkdir())
                                    System.out.println("Created new group directory");
                                else if (file.exists())
                                    System.out.println("Found group directory");
                                else
                                    System.out.println("Error creating group directory");

                                // Create file on server
                                file = new File("shared_files/" + group + "/" + remotePath.replace('/', '_'));
                                file.createNewFile();
                                FileOutputStream   fos = new FileOutputStream(file);
                                CipherOutputStream cos = new CipherOutputStream(fos, ct.getFileCipher("ENCRYPT", groupKey, IV));
                                System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

                                // Tell client that server is ready
                                ct.incrementN();
                                response = new Envelope("READY");
                                response.addObject(ct.getN());
                                output.writeObject(ct.encrypt(response));   // Send response
                                output.writeObject(ct.getDigest(response)); // Send digest

                                // Receive message
                                e = (Envelope)ct.decrypt((byte[])input.readObject());

                                // Verify message integrity
                                if (ct.verifyMessage(e, (byte[])input.readObject()))
                                    ct.incrementN();
                                else
                                {// Verification failed
                                    System.out.println("Message Verification Failed");
                                    socket.close();  // Close the socket
                                    proceed = false; // End this communication loop
                                }

                                while (e.getMessage().compareTo("CHUNK") == 0)
                                {// There is a chunk to read
                                    cos.write((byte[])e.getObjContents().get(1), 0, (Integer)e.getObjContents().get(2));

                                    // Tell client that server is ready
                                    ct.incrementN();
                                    response = new Envelope("READY");
                                    response.addObject(ct.getN());
                                    output.writeObject(ct.encrypt(response));   // Send response
                                    output.writeObject(ct.getDigest(response)); // Send digest

                                    // Receive message
                                    e = (Envelope)ct.decrypt((byte[])input.readObject());

                                    // Verify message integrity
                                    if (ct.verifyMessage(e, (byte[])input.readObject()))
                                        ct.incrementN();
                                    else
                                    {// Verification failed
                                        System.out.println("Message Verification Failed");
                                        socket.close();  // Close the socket
                                        proceed = false; // End this communication loop
                                    }
                                }

                                if (e.getMessage().compareTo("EOF") == 0)
                                {// Reached end of file
                                    System.out.printf("Transfer successful file %s\n", remotePath);
                                    FileServer.fileList.addFile(yourToken.getSubject(), group, file.getPath());

                                    // Tell client success
                                    ct.incrementN();
                                    response = new Envelope("OK");
                                    response.addObject(ct.getN());
                                }
                                else
                                {// Error
                                    System.out.printf("Error reading file %s from client\n", remotePath);
                                    ct.incrementN();
                                    response = new Envelope("ERROR-TRANSFER");
                                    response.addObject(ct.getN());
                                }

                                cos.close();
                                fos.close();
                            }
                        }
                    }
                    // Send response
                    output.writeObject(ct.encrypt(response));
                }
                /* Client wants to download file */
                else if (e.getMessage().compareTo("DOWNLOADF") == 0)
                {
                    String       remotePath = (String)e.getObjContents().get(1);       // Extract filename
                    SecretKey    groupKey   = (SecretKey)e.getObjContents().get(2);    // Extract group key
                    byte[]       IV         = (byte[])e.getObjContents().get(3);       // Extract group IV
                    SignedObject so         = (SignedObject)e.getObjContents().get(4); // Extract SignedObject
                    UserToken    t          = verifyToken(so, KGS);                    // Extract requester token
                    ShareFile    sf         = FileServer.fileList.getFile(remotePath); // Get the file

                    // Check parameters -- don't know why the skeleton code was set up like this but whatever
                    //                  -- this should obviously happen before the parameters are set, not after
                    //                  -- TODO: Change this to be set up like upload
                    if (e.getObjContents().size() < 5)
                    {// Parameters are missing
                        ct.incrementN();
                        e = new Envelope("FAIL-BADCONTENTS");
                        e.addObject(ct.getN());
                        output.writeObject(ct.encrypt(e)); // Send response
                    }
                    else if (sf == null)
                    {// File does not exist in FileList
                        ct.incrementN();
                        System.out.printf("Error: File %s doesn't exist\n", remotePath);
                        e = new Envelope("ERROR_FILEMISSING");
                        e.addObject(ct.getN());
                        output.writeObject(ct.encrypt(e)); // Send response
                    }
                    else if (!t.getGroups().contains(sf.getGroup()))
                    {// File not in client's groups
                        ct.incrementN();
                        System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                        e = new Envelope("ERROR_PERMISSION");
                        e.addObject(ct.getN());
                        output.writeObject(ct.encrypt(e)); // Send response
                    }
                    else
                    {
                        try
                        {   // PROB GONNA BE ERROR RIGHT HERE
                            File f = new File(sf.getPath());

                            if (!f.exists())
                            {// File does not exist on server directory
                                System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
                                ct.incrementN();
                                e = new Envelope("ERROR_NOTONDISK"); // Tell client file does not exist
                                e.addObject(ct.getN());
                                output.writeObject(ct.encrypt(e)); // Send response
                            }
                            else
                            {
                                FileInputStream   fis = new FileInputStream(f);
                                CipherInputStream cis = new CipherInputStream(fis, ct.getFileCipher("DECRYPT", groupKey, IV));

                                do
                                {// Send file in chunks
                                    byte[] buf = new byte[4096];

                                    if (e.getMessage().compareTo("DOWNLOADF") != 0)
                                    {// Message is wrong
                                        System.out.printf("Server error: %s\n", e.getMessage());
                                        break;
                                    }
                                    // Tell client a chunk is coming
                                    e = new Envelope("CHUNK");
                                    int n = cis.read(buf); // Can throw an IOException
                                    if (n > 0)             // Amount read
                                        System.out.printf(".");
                                    else if (n < 0)        // Didn't read in
                                        System.out.println("Read error");
                                    ct.incrementN();
                                    e.addObject(ct.getN());              // Add N
                                    e.addObject(buf);                    // Add chunk to be sent
                                    e.addObject(new Integer(n));         // Add number of bytes in chunk
                                    output.writeObject(ct.encrypt(e));   // Send response
                                    output.writeObject(ct.getDigest(e)); // Send digest

                                    // Get message from client
                                    e = (Envelope)ct.decrypt((byte[])input.readObject());

                                    // Verify message integrity
                                    if (ct.verifyMessage(e, (byte[])input.readObject()))
                                        ct.incrementN();
                                    else
                                    {// Verification failed
                                        System.out.println("Message Verification Failed");
                                        socket.close();  // Close the socket
                                        proceed = false; // End this communication loop
                                    }
                                }
                                while (cis.available() > 0);

                                cis.close();
                                fis.close();

                                // If server indicates success, return the member list
                                if (e.getMessage().compareTo("DOWNLOADF") == 0)
                                {
                                    ct.incrementN();
                                    e = new Envelope("EOF");             // Tell client end of file
                                    e.addObject(ct.getN());              // Add N
                                    output.writeObject(ct.encrypt(e));   // Send response
                                    output.writeObject(ct.getDigest(e)); // Send digest

                                    // Get message from client
                                    e = (Envelope)ct.decrypt((byte[])input.readObject());

                                    // Verify message integrity
                                    if (ct.verifyMessage(e, (byte[])input.readObject()))
                                        ct.incrementN();
                                    else
                                    {// Verification failed
                                        System.out.println("Message Verification Failed");
                                        socket.close();  // Close the socket
                                        proceed = false; // End this communication loop
                                    }

                                    if (e.getMessage().compareTo("OK") == 0)
                                        System.out.printf("File data upload successful\n");
                                    else
                                        System.out.printf("Upload failed: %s\n", e.getMessage());
                                }
                                else
                                    System.out.printf("Upload failed: %s\n", e.getMessage());
                            }
                        }
                        catch (Exception e1)
                        {
                            System.err.println("Error: " + e.getMessage());
                            e1.printStackTrace(System.err);
                        }
                    }
                }
                /* Client wants to delete file */
                else if (e.getMessage().compareTo("DELETEF") == 0)
                {
                    String       remotePath = (String)e.getObjContents().get(1);       // Extract filename
                    SignedObject so         = (SignedObject)e.getObjContents().get(2); // Extract SignedObject
                    UserToken    t          = verifyToken(so, KGS);                    // Extract requester token
                    ShareFile    sf         = FileServer.fileList.getFile(remotePath); // Get the file

                    // Check parameters -- TODO: fix this same thing with checking the params in here as well
                    if (e.getObjContents().size() < 3)
                    {
                        ct.incrementN();
                        e = new Envelope("FAIL-BADCONTENTS");   // Tell client parameters are missing
                        e.addObject(ct.getN());
                    }
                    else if (sf == null)
                    {// File does not exist in FileList
                        System.out.printf("Error: File %s doesn't exist\n", remotePath);
                        ct.incrementN();
                        e = new Envelope("ERROR_DOESNTEXIST");  // Tell client file is missing
                        e.addObject(ct.getN());
                    }
                    else if (!t.getGroups().contains(sf.getGroup()))
                    {// File not in requester's groups
                        System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                        ct.incrementN();
                        e = new Envelope("ERROR_PERMISSION");   // Tell client permission is wrong
                        e.addObject(ct.getN());
                    }
                    else
                    {
                        try
                        {
                            File f = new File(sf.getPath());

                            if (!f.exists())
                            {// File does not exist on server directory
                                System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
                                ct.incrementN();
                                e = new Envelope("ERROR_FILEMISSING"); // Tell client file does not exist
                                e.addObject(ct.getN());
                            }
                            else if (f.delete())
                            {
                                System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
                                FileServer.fileList.removeFile(remotePath);
                                ct.incrementN();
                                e = new Envelope("OK"); // Tell client delete successful
                                e.addObject(ct.getN());
                            }
                            else
                            {
                                System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
                                ct.incrementN();
                                e = new Envelope("ERROR_DELETE");
                                e.addObject(ct.getN());
                            }
                        }
                        catch (Exception e1)
                        {
                            System.err.println("Error: " + e1.getMessage());
                            e1.printStackTrace(System.err);
                            ct.incrementN();
                            e = new Envelope(e1.getMessage());
                            e.addObject(ct.getN());
                        }
                    }
                    // Send response
                    output.writeObject(ct.encrypt(e));
                    output.writeObject(ct.getDigest(e));
                }
                /* Client wants to disconnect */
                else if (e.getMessage().equals("DISCONNECT"))
                {
                    socket.close();
                    proceed = false;
                }
                else
                {// Server does not understand client request
                    ct.incrementN();
                    response = new Envelope("FAIL-BADMSG");
                    response.addObject(ct.getN());
                    output.writeObject(ct.encrypt(response)); // Send response
                }

                // Send digest of response message
                if (response != null)
                    output.writeObject(ct.getDigest(response));
            } while (proceed);
        }
        catch (Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    /**
     * Private method that verifies and extracts a SignedObject containing the UserToken
     *
     * @param token The SignedObject containing the UserToken
     * @param publicKey The GroupServer's public key
     *
     * @return The UserToken
     */
    private UserToken verifyToken(SignedObject token, PublicKey publicKey)
    {
        try
        {// Create Verification Engine
            Signature verificationEngine = Signature.getInstance("SHA1withRSA", "BC");

            // Return the token if the signedObject is verified
            if (token.verify(publicKey, verificationEngine))
            {// Check to make sure this is the correct file server
                UserToken temp = (UserToken)token.getObject();
                if (temp.getFileServerID().equals(my_fs.getName() + my_fs.getPort()))
                    return temp;
                return null;
            }
            else
                return null;
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }
}
