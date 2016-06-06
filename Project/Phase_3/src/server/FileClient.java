package server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;

/**
 * FileClient provides all the client functionality regarding the file server
 */
public class FileClient extends Client implements FileClientInterface
{
    private Cipher encryptionCipher; // Cipher for AES encryption
    private Cipher decryptionCipher; // Cipher for AES decryption

    /**
     * Handles the handshake protocol between the FileClient and the FileThread
     *
     * @return true if the handshake was successful, false otherwise
     */
    public boolean handshake()
    {
        try
        {
            // Receive PublicKey from file server
            PublicKey publicKey = (PublicKey)input.readObject();

            // Generate RC
            byte[] bytes = new byte[8];
            SecureRandom random = new SecureRandom();
            random.nextBytes(bytes);
            BigInteger RC = new BigInteger(bytes);

            // Encrypt and send RC using public key from file server
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            output.writeObject(cipher.doFinal(RC.toByteArray()));

            // Receive challenge response
            BigInteger RCResponse = (BigInteger)input.readObject();

            // Check challenge response
            if (RCResponse.compareTo(new BigInteger(String.valueOf(RC.intValue() + 1))) != 0)
                return false;

            // Generate session key and IV
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey sessionKey = keyGenerator.generateKey();
            byte[] IV = new byte[16];
            random.nextBytes(IV);

            // Encrypt and send session key and IV
            output.writeObject(cipher.doFinal(sessionKey.getEncoded()));
            output.writeObject(cipher.doFinal(IV));

            // Set AES cipher details
            IvParameterSpec IVPS = new IvParameterSpec(IV);
            encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, sessionKey, IVPS);
            decryptionCipher.init(Cipher.DECRYPT_MODE, sessionKey, IVPS);

            return true;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Private method to handle serializing and encrypting Envelopes
     *
     * @param envelope The unencrypted envelope
     *
     * @return The encrypted data
     *
     * @throws IOException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private byte[] encryptEnvelope(Envelope envelope) throws IOException, BadPaddingException, IllegalBlockSizeException
    {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream    o = new ObjectOutputStream(b);
        o.writeObject(envelope);

        return encryptionCipher.doFinal(b.toByteArray());
    }

    /**
     * Private method to handle decrypting and deserializing Envelopes
     *
     * @param envelope The encrypted envelope
     *
     * @return The unencrypted data
     *
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private Envelope decryptEnvelope(byte[] envelope) throws BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException
    {
        byte[] bytes = decryptionCipher.doFinal(envelope);

        ByteArrayInputStream b = new ByteArrayInputStream(bytes);
        ObjectInputStream    o = new ObjectInputStream(b);

        return (Envelope)o.readObject();
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
	public boolean delete(String filename, UserToken token)
    {
		String remotePath;

        // Check for '/' at the beginning of filename
		if (filename.charAt(0) == '/')
			remotePath = filename.substring(1);
		else
			remotePath = filename;

        // Tell server to delete file
		Envelope env = new Envelope("DELETEF");
	    env.addObject(remotePath);  // Add the filepath
	    env.addObject(token);       // Add the requester's token

        try
        {// Send the message
			output.writeObject(encryptEnvelope(env));

            // Receive server response
		    env = decryptEnvelope((byte[])input.readObject());
			if (env.getMessage().compareTo("OK") == 0)
				System.out.printf("File %s deleted successfully\n", filename);
			else
            {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		}
        catch (IOException | ClassNotFoundException | IllegalBlockSizeException | BadPaddingException e1)
        {
			e1.printStackTrace();
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
	public boolean download(String sourceFile, String destFile, UserToken token)
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
                Envelope env = new Envelope("DOWNLOADF");
                env.addObject(sourceFile);                // Add the filename on server
                env.addObject(token);                     // Add the requester token
                output.writeObject(encryptEnvelope(env)); // Send message

                // Receive server response
                env = decryptEnvelope((byte[])input.readObject());

                while (env.getMessage().compareTo("CHUNK") == 0)
                {// File is arriving in chunks
                    fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
                    System.out.printf(".");
                    env = new Envelope("DOWNLOADF");                   // Tell the server to send next chunk
                    output.writeObject(encryptEnvelope(env));          // Send message
                    env = decryptEnvelope((byte[])input.readObject()); // Receive response
                }

                fos.close();

                if (env.getMessage().compareTo("EOF") == 0)
                {// Reached the end of file
                    fos.close();
                    System.out.printf("\nTransfer successful file %s\n", sourceFile);
                    env = new Envelope("OK");                  // Tell the server it was a success
                    output.writeObject(encryptEnvelope(env));  // Send message
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
        catch (IOException e1)
        {
            System.out.printf("Error couldn't create file %s\n", destFile);
            return false;
        }
        catch (ClassNotFoundException | IllegalBlockSizeException | BadPaddingException e1)
        {
            e1.printStackTrace();
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
	public List<String> listFiles(UserToken token)
    {
		 try
		 {
			 Envelope message, e;

			 // Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token);                     // Add requester token
             output.writeObject(encryptEnvelope(message)); // Send message

             // Receive response
			 e = decryptEnvelope((byte[])input.readObject());
			 
			 // If server indicates success, return the member list
			 if (e.getMessage().equals("OK"))
				return (List<String>)e.getObjContents().get(0); // This cast creates compiler warnings. Sorry.

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
	public boolean upload(String sourceFile, String destFile, String group, UserToken token)
    {
        // Check for and append a leading '/'
		if (destFile.charAt(0) != '/')
			 destFile = "/" + destFile;

		try
		{
			Envelope message, env;

            // Tell the server to return the member list
            message = new Envelope("UPLOADF");
            message.addObject(destFile);                  // Add filename on server
            message.addObject(group);                     // Add groupname
            message.addObject(token);                     // Add requester token
            output.writeObject(encryptEnvelope(message)); // Send message

            // Stream to local file
            FileInputStream fis = new FileInputStream(sourceFile);
            // Receive server response
            env = decryptEnvelope((byte[])input.readObject());

            // If server indicates success, return the member list
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

                message.addObject(buf);                       // Add the chunk
                message.addObject(new Integer(n));
                output.writeObject(encryptEnvelope(message)); // Send message

                // Receive response
                env = decryptEnvelope((byte[])input.readObject());
            } while (fis.available() > 0);

            // If server indicates success, return the member list
            if (env.getMessage().compareTo("READY") == 0)
            {
                // Tell server it has reached end of file
                message = new Envelope("EOF");
                output.writeObject(encryptEnvelope(message)); // Send message

                // Receive response
                env = decryptEnvelope((byte[])input.readObject());
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
                Envelope message = new Envelope("DISCONNECT");
                output.writeObject(encryptEnvelope(message));
            }
            catch(Exception e)
            {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        }
    }
}

