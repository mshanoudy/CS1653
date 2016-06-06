package server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;

/**
 * GroupClient provides all the client functionality regarding the group server
 */
public class GroupClient extends Client implements GroupClientInterface
{
    private String password;         // User password
    private Cipher encryptionCipher; // Cipher for AES encryption
    private Cipher decryptionCipher; // Cipher for AES decryption

    public boolean handshake()
    {
        try
        {
            // Receive PublicKey from group server
            PublicKey publicKey = (PublicKey)input.readObject();

            // Generate RC
            byte[] bytes = new byte[8];
            SecureRandom random = new SecureRandom();
            random.nextBytes(bytes);
            BigInteger RC = new BigInteger(bytes);

            // Encrypt and send RC using public key from group server
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


            // Encrypt and send session key, IV, username, password
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
     * @throws javax.crypto.BadPaddingException
     * @throws javax.crypto.IllegalBlockSizeException
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
     * Method used to get a token from the group server.  Right now,
     * there are no security checks.
     *
     * @param username The user whose token is being requested
     *
     * @return A UserToken describing the permissions of "username."
     *         If this user does not exist, a null value will be returned.
     *
     */
    public UserToken getToken(String username)
    {
        try
        {
            UserToken token;
            Envelope message, response;

            // Tell the server to return a token.
            message = new Envelope("GET");
            message.addObject(username); // Add user name string
            message.addObject(password); // Add password
            output.writeObject(encryptEnvelope(message)); // Send message

            // Get the response from the server
            response = decryptEnvelope((byte[])input.readObject());

            // Successful response
            if(response.getMessage().equals("OK"))
                if (response.getObjContents().size() == 1)
                {
                    token = (Token)response.getObjContents().get(0);
                    return token;
                }

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
     * Creates a new user.  This method should only succeed if the
     * user invoking it is a member of the special group "ADMIN".
     *
     * @param username The name of the user to create
     * @param token    The token of the user requesting the create operation
     *
     * @return true if the new user was created, false otherwise
     *
     */
    public boolean createUser(String username, String password, UserToken token)
    {
        try
        {
            Envelope message, response;

            // Tell the server to create a user
            message = new Envelope("CUSER");
            message.addObject(username); // Add user name string
            message.addObject(password); // Add user password
            message.addObject(token);    // Add the requester token
            output.writeObject(encryptEnvelope(message)); // Send message

            // Get server response
            response = decryptEnvelope((byte[])input.readObject());

            // If server indicates success, return true
            return response.getMessage().equals("OK");
        }
        catch (Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    /**
     * Deletes a user.  This method should only succeed if the user
     * invoking it is a member of the special group "ADMIN".  Deleting
     * a user should also remove him or her from all existing groups.
     *
     * @param username The name of the user to delete
     * @param token    The token of the user requesting the delete operation
     *
     * @return true if the user was deleted, false otherwise
     *
     */
    public boolean deleteUser(String username, UserToken token)
    {
        try
        {
            Envelope message,
                    response;

            // Tell the server to delete a user
            message = new Envelope("DUSER");
            message.addObject(username); // Add user name
            message.addObject(token);    // Add requester token
            output.writeObject(encryptEnvelope(message)); // Send message

            // Get server response
            response = decryptEnvelope((byte[])input.readObject());

            // If server indicates success, return true
            return response.getMessage().equals("OK");
        }
        catch (Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    /**
     * Creates a new group.  Any user may create a group, provided
     * that it does not already exist.
     *
     * @param groupname The name of the group to create
     * @param token     The token of the user requesting the create operation
     *
     * @return true if the new group was created, false otherwise
     *
     */
    public boolean createGroup(String groupname, UserToken token)
    {
        try
        {
            Envelope message,
                    response;

            // Tell the server to create a group
            message = new Envelope("CGROUP");
            message.addObject(groupname); // Add the group name string
            message.addObject(token);     // Add the requester token
            output.writeObject(encryptEnvelope(message));  // Send message

            // Get server response
            response = decryptEnvelope((byte[])input.readObject());

            // If server indicates success, return true
            return response.getMessage().equals("OK");
        }
        catch (Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    /**
     * Deletes a group.  This method should only succeed if the user
     * invoking it is the user that originally created the group.
     *
     * @param groupname The name of the group to delete
     * @param token     The token of the user requesting the delete operation
     *
     * @return true if the group was deleted, false otherwise
     *
     */
    public boolean deleteGroup(String groupname, UserToken token)
    {
        try
        {
            Envelope message,
                    response;

            // Tell the server to delete a group
            message = new Envelope("DGROUP");
            message.addObject(groupname); // Add group name string
            message.addObject(token);     // Add requester token
            output.writeObject(encryptEnvelope(message));  // Send message

            // Get server response
            response = decryptEnvelope((byte[])input.readObject());

            // If server indicates success, return true
            return response.getMessage().equals("OK");
        }
        catch (Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    /**
     * Lists the members of a group.  This method should only succeed
     * if the user invoking the operation is the owner of the
     * specified group.
     *
     * @param group The group whose membership list is requested
     * @param token The token of the user requesting the list
     *
     * @return A List of group members.  Note that an empty list means
     *         a group has no members, while a null return indicates
     *         an error.
     *
     */
    @SuppressWarnings("unchecked")
    public List<String> listMembers(String group, UserToken token)
    {
        try
        {
            Envelope message,
                    response;

            // Tell the server to return the member list
            message = new Envelope("LMEMBERS");
            message.addObject(group);    // Add group name string
            message.addObject(token);    // Add requester token
            output.writeObject(encryptEnvelope(message)); // Send message

            // Get server response
            response = decryptEnvelope((byte[])input.readObject());

            // If server indicates success, return the member list
            if(response.getMessage().equals("OK"))
                return (List<String>)response.getObjContents().get(0); // This cast creates compiler warnings. Sorry.

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
     * Adds a user to some group.  This method should succeed if
     * the user invoking the operation is the owner of the group.
     *
     * @param username  The user to add
     * @param groupname The name of the group to which user should be added
     * @param token The token of the user requesting the create operation
     *
     * @return true if the user was added, false otherwise
     *
     */
    public boolean addUserToGroup(String username, String groupname, UserToken token)
    {
        try
        {
            Envelope message,
                    response;

            // Tell the server to add a user to the group
            message = new Envelope("AUSERTOGROUP");
            message.addObject(username);  // Add user name string
            message.addObject(groupname); // Add group name string
            message.addObject(token);     // Add requester token
            output.writeObject(encryptEnvelope(message));  // Send message

            // Get server response
            response = decryptEnvelope((byte[])input.readObject());

            // If server indicates success, return true
            return response.getMessage().equals("OK");
        }
        catch (Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    /**
     * Removes a user from some group.  This method should succeed if
     * the user invoking the operation is the owner of the group.
     *
     * @param username  The name of the user to remove
     * @param groupname The name of the group from which user should be removed
     * @param token The token of the user requesting the remove operation
     *
     * @return true if the user was removed, false otherwise
     *
     */
    public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
    {
        try
        {
            Envelope message,
                    response;

            //Tell the server to remove a user from the group
            message = new Envelope("RUSERFROMGROUP");
            message.addObject(username);  // Add user name string
            message.addObject(groupname); // Add group name string
            message.addObject(token);     // Add requester token
            output.writeObject(encryptEnvelope(message));  // Send message

            // Get server response
            response = decryptEnvelope((byte[])input.readObject());

            // If server indicates success, return true
            return response.getMessage().equals("OK");
        }
        catch (Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    /**
     * Sets the password for the user of this group client
     *
     * @param password The password
     *
     */
    public void setPassword(String password)
    {
        this.password = password;
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
