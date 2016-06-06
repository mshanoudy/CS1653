package server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignedObject;
import java.util.List;

/**
 * FileClient provides all the client functionality regarding the file server
 */
public class FileClient extends Client implements FileClientInterface
{
    private CryptoTools ct;
    private String fileServerID; // server name + port number

    /**
     * Handles the handshake protocol between the FileClient and the FileThread
     *
     * @param KGS The Group Server's public key
     *
     * @return true if the handshake was successful, false otherwise
     */
    public boolean handshake(PublicKey KGS)
    {
        try
        {// Set provider as BouncyCastle
            Security.addProvider(new BouncyCastleProvider());

            // Receive PublicKey from file server
            PublicKey publicKey = (PublicKey)input.readObject();

            // Receive fileServerID
            fileServerID = (String)input.readObject();

            // Generate RC
            byte[] rndmBytes = new byte[8];
            SecureRandom random = new SecureRandom();
            random.nextBytes(rndmBytes);
            BigInteger RC = new BigInteger(rndmBytes);

            // Generate KS and IV
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
            keyGenerator.init(128);
            SecretKey KS = keyGenerator.generateKey();
            byte[]    IV = new byte[16];
            random.nextBytes(IV);

            // Generate KH
            keyGenerator = KeyGenerator.getInstance("HmacSHA1", "BC");
            keyGenerator.init(128);
            SecretKey KH = keyGenerator.generateKey();

            // Generate N
            random.nextBytes(rndmBytes);
            int N = new BigInteger(rndmBytes).intValue();

            // Set up CryptoTools
            ct = new CryptoTools(N, KS, IV, KH);

            // Set RSA Cipher
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Encrypt and send N, KS, IV, and RC
            output.writeObject(cipher.doFinal(rndmBytes));          // N
            output.writeObject(cipher.doFinal(ct.toByteArray(KS))); // KS
            output.writeObject(cipher.doFinal(IV));                 // IV
            output.writeObject(cipher.doFinal(ct.toByteArray(KH))); // KH
            output.writeObject(KGS);                                // KGS
            output.writeObject(cipher.doFinal(ct.toByteArray(RC))); // RC

            // Receive cipher text and HMAC from group server
            Envelope envelope = (Envelope)ct.decrypt((byte[])input.readObject());
            byte[] digest = (byte[])input.readObject();

            // Verify message
            if (ct.verifyMessage(envelope, digest))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

            // Check challenge response
            BigInteger RCResponse = (BigInteger)envelope.getObjContents().get(1);
            return RCResponse.compareTo(new BigInteger(String.valueOf(RC.intValue() + 1))) == 0;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Deletes a file from the server.  The user must be a member of
     * the group with which this file is shared.
     *
     * @param filename The file to delete
     * @param token    The token of the user requesting the delete
     *
     * @return true on success, false on failure
     */
	public boolean delete(String filename, SignedObject token)
    {
		String remotePath;

        // Check for '/' at the beginning of filename
		if (filename.charAt(0) == '/')
			remotePath = filename.substring(1);
		else
			remotePath = filename;

        // Tell server to delete file
        ct.incrementN();
		Envelope env = new Envelope("DELETEF");
        env.addObject(ct.getN());   // Add N
	    env.addObject(remotePath);  // Add the file path
	    env.addObject(token);       // Add the requester token

        try
        {// Send the message and digest
			output.writeObject(ct.encrypt(env));
            output.writeObject(ct.getDigest(env));

            // Receive server response
		    env = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(env, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

			if (env.getMessage().compareTo("OK") == 0)
				System.out.printf("File %s deleted successfully\n", filename);
			else
            {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		}
        catch (Exception e)
        {
			e.printStackTrace();
		}

        return true;
	}

    /**
     * Downloads a file from the server.  The user must be a member of
     * the group with which this file is shared.
     *
     * @param sourceFile The filename used on the server
     * @param destFile   The filename to use locally
     * @param token      The token of the user uploading the file
     *
     * @return true on success, false on failure
     */
	public boolean download(String sourceFile, String destFile, SecretKey groupKey, byte[] IV, SignedObject token)
    {
        // Check for and remove leading '/'
		if (sourceFile.charAt(0) == '/')
			sourceFile = sourceFile.substring(1);

        // Create local file
		File file = new File(destFile);
	    try
        {
            if (!file.exists())
            {// Create local copy of the file
                file.createNewFile();
                FileOutputStream fos = new FileOutputStream(file);

                // Tell server to download file
                ct.incrementN();
                Envelope env = new Envelope("DOWNLOADF");
                env.addObject(ct.getN());  // Add N
                env.addObject(sourceFile); // Add the filename on server
                env.addObject(groupKey);   // Add the group key
                env.addObject(IV);         // Add the IV
                env.addObject(token);      // Add the requester token
                output.writeObject(ct.encrypt(env));   // Send message
                output.writeObject(ct.getDigest(env)); // Send digest

                // Receive server response
                env = (Envelope)ct.decrypt((byte[])input.readObject());

                // Verify message
                if (ct.verifyMessage(env, (byte[])input.readObject()))
                    ct.incrementN();
                else
                {// Verification failed
                    System.out.println("Message Verification Failed");
                    disconnect();
                    System.exit(0);
                }

                while (env.getMessage().compareTo("CHUNK") == 0)
                {// File is arriving in chunks
                    fos.write((byte[])env.getObjContents().get(1), 0, (Integer)env.getObjContents().get(2));
                    System.out.printf(".");

                    // Tell the server to send next chunk
                    ct.incrementN();
                    env = new Envelope("DOWNLOADF");
                    env.addObject(ct.getN());
                    output.writeObject(ct.encrypt(env));   // Send message
                    output.writeObject(ct.getDigest(env)); // Send digest

                    // Receive response
                    env = (Envelope)ct.decrypt((byte[])input.readObject());
                    // Verify message
                    if (ct.verifyMessage(env, (byte[])input.readObject()))
                        ct.incrementN();
                    else
                    {// Verification failed
                        System.out.println("Message Verification Failed");
                        disconnect();
                        System.exit(0);
                    }
                }

                fos.close();

                if (env.getMessage().compareTo("EOF") == 0)
                {// Reached the end of file
                    fos.close();
                    System.out.printf("\nTransfer successful file %s\n", sourceFile);

                    // Tell the server it was a success
                    ct.incrementN();
                    env = new Envelope("OK");
                    env.addObject(ct.getN());
                    output.writeObject(ct.encrypt(env));   // Send message
                    output.writeObject(ct.getDigest(env)); // Send digest
                }
                else
                {// Something went wrong with transfer
                    System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
                    file.delete();
                    return false;
                }
            }
            else
            {// File exists already
                System.out.printf("Error couldn't create file %s\n", destFile);
                return false;
            }
        }
        catch (Exception e)
        {
            System.out.printf("Error couldn't create file %s\n", destFile);
            return false;
        }

        return true;
	}

    /**
     * Retrieves a list of files that are allowed to be displayed
     * members of the groups encoded in the supplied user token.
     *
     * @param token The UserToken object assigned to the user invoking this operation
     *
     * @return A list of filenames, null on failure
     */
	@SuppressWarnings("unchecked")
	public List<String> listFiles(SignedObject token)
    {
		 try
		 {
			 Envelope message, e;

			 // Tell the server to return the member list
             ct.incrementN();
			 message = new Envelope("LFILES");
             message.addObject(ct.getN()); // Add N
			 message.addObject(token);     // Add requester token
             output.writeObject(ct.encrypt(message));   // Send message
             output.writeObject(ct.getDigest(message)); // Send digest

             // Receive response
			 e = (Envelope)ct.decrypt((byte[])input.readObject());

             // Verify message
             if (ct.verifyMessage(e, (byte[])input.readObject()))
                 ct.incrementN();
             else
             {// Verification failed
                 System.out.println("Message Verification Failed");
                 disconnect();
                 System.exit(0);
             }

			 // If server indicates success, return the member list
			 if (e.getMessage().equals("OK"))
				return (List<String>)e.getObjContents().get(1); // This cast creates compiler warnings

			 return null;
		 }
		 catch (Exception e)
         {
             System.err.println("Error: " + e.getMessage());
             e.printStackTrace(System.err);
             return null;
         }
	}

    /**
     * Uploads a file to the server to be shared with members of the
     * specified group.  This method should only succeed if the
     * uploader is a member of the group that the file will be shared
     * with.
     *
     * @param sourceFile Path to the local file to upload
     * @param destFile   The filename to use on the server
     * @param group      The group to share this file with
     * @param token      The token of the user uploading the file
     *
     * @return true on success, false on failure
     */
	public boolean upload(String sourceFile, String destFile, String group, SecretKey groupKey, byte[] IV, SignedObject token)
    {
        // Check for and append a leading '/'
		if (destFile.charAt(0) != '/')
			 destFile = "/" + destFile;

		try
		{
			Envelope message, env;

            // Tell the server to return the member list
            ct.incrementN();
            message = new Envelope("UPLOADF");
            message.addObject(ct.getN()); // Add N
            message.addObject(destFile);  // Add filename on server
            message.addObject(group);     // Add group name
            message.addObject(groupKey);  // Add group key
            message.addObject(IV);        // Add IV
            message.addObject(token);     // Add requester token
            output.writeObject(ct.encrypt(message));   // Send message
            output.writeObject(ct.getDigest(message)); // Send digest

            // Stream to local file
            FileInputStream fis = new FileInputStream(sourceFile);

            // Receive server response
            env = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(env, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

            // Server is ready for upload
            if (env.getMessage().equals("READY"))
                System.out.printf("Meta data upload successful\n");
            else
            {
                System.out.printf("Upload failed: %s\n", env.getMessage());
                return false;
            }

            do
            {// Send the file to server in chunks
                byte[] buf = new byte[4096];

                if (env.getMessage().compareTo("READY") != 0)
                {// If the server isn't ready
                    System.out.printf("Server error: %s\n", env.getMessage());
                    return false;
                }
                // Tell the server there is a chunk coming
                message = new Envelope("CHUNK");
                int n = fis.read(buf); // Can throw an IOException
                if (n > 0)
                    System.out.printf(".");
                else if (n < 0)
                {// Couldn't read the chunk from local file
                    System.out.println("Read error");
                    return false;
                }
                ct.incrementN();
                message.addObject(ct.getN());      // Add N
                message.addObject(buf);            // Add the chunk
                message.addObject(new Integer(n)); // Add chunk size
                output.writeObject(ct.encrypt(message));   // Send message
                output.writeObject(ct.getDigest(message)); // Send digest

                // Receive response
                env = (Envelope)ct.decrypt((byte[])input.readObject());

                // Verify message
                if (ct.verifyMessage(env, (byte[])input.readObject()))
                    ct.incrementN();
                else
                {// Verification failed
                    System.out.println("Message Verification Failed");
                    disconnect();
                    System.exit(0);
                }
            } while (fis.available() > 0);

            // If server indicates success, return the member list
            if (env.getMessage().compareTo("READY") == 0)
            {
                // Tell server it has reached end of file
                ct.incrementN();
                message = new Envelope("EOF");
                message.addObject(ct.getN());
                output.writeObject(ct.encrypt(message));   // Send message
                output.writeObject(ct.getDigest(message)); // Send digest

                // Receive response
                env = (Envelope)ct.decrypt((byte[])input.readObject());

                // Verify message
                if (ct.verifyMessage(env, (byte[])input.readObject()))
                    ct.incrementN();
                else
                {// Verification failed
                    System.out.println("Message Verification Failed");
                    disconnect();
                    System.exit(0);
                }

                if (env.getMessage().compareTo("OK") == 0)
                    System.out.printf("\nFile data upload successful\n");
                else
                {
                    System.out.printf("\nUpload failed: %s\n", env.getMessage());
                    return false;
                }
            }
            else
            {
                System.out.printf("Upload failed: %s\n", env.getMessage());
                return false;
            }
		}
        catch (Exception e1)
		{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
		}

		return true;
	}

    /**
     * Override of disconnect() that makes sure the envelope is encrypted
     */
    @Override public void disconnect()
    {
        if (isConnected())
        {
            try
            {
                ct.incrementN();
                Envelope message = new Envelope("DISCONNECT");
                message.addObject(ct.getN());
                output.writeObject(ct.encrypt(message));   // Send message
                output.writeObject(ct.getDigest(message)); // Send digest
            }
            catch(Exception e)
            {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        }
    }

    /**
     * Getter for fileServerID
     *
     * @return The file server's ID
     */
    public String getFileServerID()
    {
        return fileServerID;
    }
}

