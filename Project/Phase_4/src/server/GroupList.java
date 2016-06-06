package server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.SecureRandom;
import java.security.Security;
import java.util.*;

/**
 * This list represents the groups on GroupServer
 */
public class GroupList implements Serializable
{
    private static final long serialVersionUID = 7600343803563417993L;
    private Hashtable<String, Group> list = new Hashtable<>(); // list of groups

    /**
     * Adds some group to GroupList
     *
     * @param groupname The group
     */
    public synchronized void addGroup(String groupname)
    {
        Group newGroup = new Group();
        list.put(groupname, newGroup);
    }

    /**
     * Deletes some group from GroupList
     *
     * @param groupname The group
     */
    public synchronized void deleteGroup(String groupname)
    {
        list.remove(groupname);
    }

    /**
     * Checks if some group exists in GroupList
     *
     * @param groupname The group
     *
     * @return true is group was found, false otherwise
     */
    public synchronized boolean checkGroup(String groupname)
    {
        return list.containsKey(groupname);
    }

    /**
     * Returns a list of group members within some group
     *
     * @param groupname The group
     *
     * @return The list of members, null otherwise
     */
    public synchronized ArrayList<String> getGroupMembers(String groupname)
    {
        return list.get(groupname).getMembers();
    }

    /**
     * Returns the owner of some group
     *
     * @param groupname The group
     *
     * @return The owner of group, null otherwise
     */
    public synchronized String getGroupOwner(String groupname)
    {
        return list.get(groupname).getOwner();
    }

    /**
     * Adds some member to some group
     *
     * @param username The member
     * @param groupname The group
     */
    public synchronized void addMember(String username, String groupname)
    {
        list.get(groupname).addMember(username);
    }

    /**
     * Removes some member from some group,
     * Deletes the group if member is owner
     *
     * @param username The member
     * @param groupname The group
     */
    public synchronized void removeMember(String username, String groupname)
    { // deletes group if removed member is owner
        if ( list.get(groupname).getOwner().equals(username) )
            deleteGroup(groupname);
        else
            list.get(groupname).removeMember(username);
    }

    /**
     * Sets the owner of some group to some member
     *
     * @param username The member
     * @param groupname The group
     */
    public synchronized void setOwner(String username, String groupname)
    {
        list.get(groupname).setOwner(username);
    }

    /**
     * Gets the key of some group
     *
     * @param groupname The group
     *
     * @return The group key
     */
    public synchronized SecretKey getGroupKey(String groupname)
    {
        return list.get(groupname).getGroupKey();
    }

    /**
     * Gets the IV of some group
     *
     * @param groupname The group
     *
     * @return The initialization vector
     */
    public synchronized byte[] getGroupIV(String groupname)
    {
        return list.get(groupname).getIV();
    }

    /**
     * Represents the groups found in GroupList
     */
    class Group implements Serializable
    {
        private String            owner;    // Owner of group
        private ArrayList<String> members;  // Members in group
        private SecretKey         groupKey; // SecretKey of the group
        private byte[]            IV;       // IV associated with groupKey

        /**
         * Default constructor
         */
        public Group()
        {
            owner   = null;
            members = new ArrayList<>();

            Security.addProvider(new BouncyCastleProvider());
            try
            {
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
                keyGenerator.init(128);
                groupKey = keyGenerator.generateKey();
                IV = new byte[16];
                SecureRandom random = new SecureRandom();
                random.nextBytes(IV);
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }

        /**
         * Returns owner of this group
         *
         * @return The owner of group
         */
        public String getOwner()
        {
            return owner;
        }

        /**
         * Returns the members of this group
         *
         * @return The members of this group
         */
        public ArrayList<String> getMembers()
        {
            return members;
        }

        /**
         * Sets the owner of this group,
         * If owner is not already a member
         * set as one
         *
         * @param username The new owner
         */
        public void setOwner(String username)
        {
            addMember(username);
            owner = username;
        }

        /**
         * Adds some member to this group
         *
         * @param username The member
         */
        public void addMember(String username)
        {
            if (!members.contains(username))
                members.add(username);
        }

        /**
         * Removes some member from this group
         *
         * @param username The member
         */
        public void removeMember(String username)
        {
            if (!members.isEmpty())
                if (members.contains(username))
                    members.remove(members.indexOf(username));
        }

        /**
         * Gets the key for this group
         *
         * @return The group key
         */
        public SecretKey getGroupKey()
        {
            return groupKey;
        }

        /**
         * Gets the IV for this group
         *
         * @return The IV
         */
        public byte[] getIV()
        {
            return IV;
        }
    }
}
