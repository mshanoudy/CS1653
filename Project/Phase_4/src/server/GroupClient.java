package server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import java.security.SignedObject;
import java.util.ArrayList;
import java.util.List;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

/**
 * GroupClient provides all the client functionality regarding the group server for the client
 */
public class GroupClient extends Client implements GroupClientInterface
{
    private String      password;     // User password
    private String      fileServerID; // FileServer's ID
    private PublicKey   publicKey;    // GroupServer public key
    private CryptoTools ct;           // Handles a lot of the encryption shit

    /**
     * Method responsible for handling the GroupClient side of the handshake protocol
     *
     * @return true if handshake was successful, false otherwise
     */
    public boolean handshake()
    {
        try
        {// Set provider as BouncyCastle
            Security.addProvider(new BouncyCastleProvider());

            // Receive PublicKey from group server
            publicKey = (PublicKey)input.readObject();

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
     * Method used to get a token from the group server.  Right now,
     * there are no security checks.
     *
     * @param username The user whose token is being requested
     *
     * @return A UserToken describing the permissions of "username."
     *         If this user does not exist, a null value will be returned.
     *
     */
    public SignedObject getToken(String username)
    {
        try
        {
            SignedObject token;
            Envelope message, response;

            // Tell the server to return a token
            ct.incrementN();
            message = new Envelope("GET");
            message.addObject(ct.getN());    // Add increment value
            message.addObject(username);     // Add user name string
            message.addObject(password);     // Add password
            message.addObject(fileServerID); // Add fileServerID;
            output.writeObject(ct.encrypt(message));   // Send message
            output.writeObject(ct.getDigest(message)); // Send digest

            // Get the response from the server
            response = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(response, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

            // Successful response
            if(response.getMessage().equals("OK"))
                if (response.getObjContents().size() == 2)
                {
                    token = (SignedObject)response.getObjContents().get(1);
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
     * @param token    The SignedObject containing the token of the user requesting the create operation
     *
     * @return true if the new user was created, false otherwise
     *
     */
    public boolean createUser(String username, String password, SignedObject token)
    {
        try
        {
            Envelope message, response;

            // Tell the server to create a user
            ct.incrementN();
            message = new Envelope("CUSER");
            message.addObject(ct.getN()); // Add N
            message.addObject(username);  // Add user name string
            message.addObject(password);  // Add user password
            message.addObject(token);     // Add the requester token
            output.writeObject(ct.encrypt(message));   // Send message
            output.writeObject(ct.getDigest(message)); // Send digest

            // Get server response
            response = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(response, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

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
     * @param token    The SignedObject containing the token of the user requesting the create operation
     *
     * @return true if the user was deleted, false otherwise
     *
     */
    public boolean deleteUser(String username, SignedObject token)
    {
        try
        {
            Envelope message, response;

            // Tell the server to delete a user
            ct.incrementN();
            message = new Envelope("DUSER");
            message.addObject(ct.getN()); // Add N
            message.addObject(username);  // Add user name
            message.addObject(token);     // Add requester token
            output.writeObject(ct.encrypt(message));   // Send message
            output.writeObject(ct.getDigest(message)); // Send digest

            // Get server response
            response = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(response, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

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
     * @param token     The SignedObject containing the token of the user requesting the create operation
     *
     * @return true if the new group was created, false otherwise
     *
     */
    public boolean createGroup(String groupname, SignedObject token)
    {
        try
        {
            Envelope message, response;

            // Tell the server to create a group
            ct.incrementN();
            message = new Envelope("CGROUP");
            message.addObject(ct.getN()); // Add N
            message.addObject(groupname); // Add the group name string
            message.addObject(token);     // Add the requester token
            output.writeObject(ct.encrypt(message));   // Send message
            output.writeObject(ct.getDigest(message)); // Send digest

            // Get server response
            response = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(response, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

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
     * @param token     The SignedObject containing the token of the user requesting the create operation
     *
     * @return true if the group was deleted, false otherwise
     *
     */
    public boolean deleteGroup(String groupname, SignedObject token)
    {
        try
        {
            Envelope message, response;

            // Tell the server to delete a group
            ct.incrementN();
            message = new Envelope("DGROUP");
            message.addObject(ct.getN()); // Add N
            message.addObject(groupname); // Add group name string
            message.addObject(token);     // Add requester token
            output.writeObject(ct.encrypt(message));   // Send message
            output.writeObject(ct.getDigest(message)); // Send digest

            // Get server response
            response = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(response, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

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
     * @param token The SignedObject containing the token of the user requesting the create operation
     *
     * @return A List of group members.  Note that an empty list means
     *         a group has no members, while a null return indicates
     *         an error.
     *
     */
    @SuppressWarnings("unchecked")
    public List<String> listMembers(String group, SignedObject token)
    {
        try
        {
            Envelope message, response;

            // Tell the server to return the member list
            ct.incrementN();
            message = new Envelope("LMEMBERS");
            message.addObject(ct.getN()); // Add N
            message.addObject(group);     // Add group name string
            message.addObject(token);     // Add requester token
            output.writeObject(ct.encrypt(message));   // Send message
            output.writeObject(ct.getDigest(message)); // Send digest

            // Get server response
            response = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(response, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

            // If server indicates success, return the member list
            if(response.getMessage().equals("OK"))
                return (List<String>)response.getObjContents().get(1); // This cast creates compiler warnings. Sorry.

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
     * @param token The SignedObject containing the token of the user requesting the create operation
     *
     * @return true if the user was added, false otherwise
     *
     */
    public boolean addUserToGroup(String username, String groupname, SignedObject token)
    {
        try
        {
            Envelope message, response;

            // Tell the server to add a user to the group
            ct.incrementN();
            message = new Envelope("AUSERTOGROUP");
            message.addObject(ct.getN()); // Add N
            message.addObject(username);  // Add user name string
            message.addObject(groupname); // Add group name string
            message.addObject(token);     // Add requester token
            output.writeObject(ct.encrypt(message));   // Send message
            output.writeObject(ct.getDigest(message)); // Send digest

            // Get server response
            response = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(response, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

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
     * @param token The SignedObject containing the token of the user requesting the create operation
     *
     * @return true if the user was removed, false otherwise
     *
     */
    public boolean deleteUserFromGroup(String username, String groupname, SignedObject token)
    {
        try
        {
            Envelope message, response;

            //Tell the server to remove a user from the group
            ct.incrementN();
            message = new Envelope("RUSERFROMGROUP");
            message.addObject(ct.getN()); // Add N
            message.addObject(username);  // Add user name string
            message.addObject(groupname); // Add group name string
            message.addObject(token);     // Add requester token
            output.writeObject(ct.encrypt(message));   // Send message
            output.writeObject(ct.getDigest(message)); // Send digest

            // Get server response
            response = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(response, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

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

    public ArrayList<Object> getGroupKey(String groupname, SignedObject token)
    {
        try
        {
            Envelope message, response;

            // Tell the server you want the group key and IV
            ct.incrementN();
            message = new Envelope("GETGROUPKEY");
            message.addObject(ct.getN()); // Add N
            message.addObject(groupname); // Add group name string
            message.addObject(token);     // Add requester token
            output.writeObject(ct.encrypt(message));   // Send message
            output.writeObject(ct.getDigest(message)); // Send digest

            // Get server response
            response = (Envelope)ct.decrypt((byte[])input.readObject());

            // Verify message
            if (ct.verifyMessage(response, (byte[])input.readObject()))
                ct.incrementN();
            else
            {// Verification failed
                System.out.println("Message Verification Failed");
                disconnect();
                System.exit(0);
            }

            if (response.getMessage().equals("OK"))
            {
                ArrayList<Object> list = new ArrayList<>();
                list.add(response.getObjContents().get(1)); // Group key
                list.add(response.getObjContents().get(2)); // IV
                return list;
            }
            return null;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
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
     * Getter for the group server;s public key
     *
     * @return The public key
     */
    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    public void setFileServerID(String ID)
    {
        fileServerID = ID;
    }
}
