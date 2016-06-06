import java.util.*;

/**
 * This list represents the users on the server
 */
public class UserList implements java.io.Serializable
{
    private static final long serialVersionUID = 7600343803563417992L;
	private Hashtable<String, User> list = new Hashtable<>(); // The list of users

    /**
     * Adds some user to UserList
     *
     * @param username The user
     */
	public synchronized void addUser(String username)
	{
		User newUser = new User();
		list.put(username, newUser);
	}

    /**
     * Deletes some user to UserList
     *
     * @param username The user
     */
	public synchronized void deleteUser(String username)
	{
		list.remove(username);
	}

    /**
     * Checks if some user is in UserList
     *
     * @param username The user
     *
     * @return true is user exists, false otherwise
     */
	public synchronized boolean checkUser(String username)
	{
        return list.containsKey(username);
	}

    /**
     * Returns the groups for some user
     *
     * @param username The user
     *
     * @return The list of groups for that user
     */
	public synchronized ArrayList<String> getUserGroups(String username)
	{
		return list.get(username).getGroups();
	}

    /**
     * Returns the groups for which some user is owner
     *
     * @param username The user
     *
     * @return The list of groups that user owns
     */
	public synchronized ArrayList<String> getUserOwnership(String username)
	{
		return list.get(username).getOwnership();
	}

    /**
     * Adds some group to some user
     *
     * @param user The user
     * @param groupname The group
     */
	public synchronized void addGroup(String user, String groupname)
	{
		list.get(user).addGroup(groupname);
	}

    /**
     * Removes some group from some user
     *
     * @param user The user
     * @param groupname The group
     */
	public synchronized void removeGroup(String user, String groupname)
	{
		list.get(user).removeGroup(groupname);
	}

    /**
     * Adds ownership of some group to some user
     *
     * @param user The user
     * @param groupname The group
     */
	public synchronized void addOwnership(String user, String groupname)
	{
		list.get(user).addOwnership(groupname);
	}

    /**
     * Removes ownership of some group
     * @param user The user
     * @param groupname The group
     */
	public synchronized void removeOwnership(String user, String groupname)
	{
		list.get(user).removeOwnership(groupname);
	}

    /**
     * Represents the users found in UserList
     */
	class User implements java.io.Serializable
    {
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;    // The groups to which this user belongs
		private ArrayList<String> ownership; // The groups to which this user owns

        /**
         * Default constructor
         */
		public User()
		{
			groups    = new ArrayList<>();
			ownership = new ArrayList<>();
		}

        /**
         * Returns the groups to which this user belongs
         *
         * @return The list of groups
         */
		public ArrayList<String> getGroups()
		{
			return groups;
		}

        /**
         * Returns the groups to which this user is owner
         *
         * @return The list of groups
         */
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}

        /**
         * Adds a group to this user's list of groups
         *
         * @param group The group
         */
		public void addGroup(String group)
		{
			groups.add(group);
		}

        /**
         * Removes a group from this user's list of groups
         *
         * @param group The group
         */
		public void removeGroup(String group)
		{
			if (!groups.isEmpty())
				if (groups.contains(group))
					groups.remove(groups.indexOf(group));
		}

        /**
         * Adds ownership of a group to this user's list
         *
         * @param group The group
         */
		public void addOwnership(String group)
		{
			ownership.add(group);
		}

        /**
         * Removes ownership of a group from this user's list
         *
         * @param group The group
         */
		public void removeOwnership(String group)
		{
			if (!ownership.isEmpty())
				if (ownership.contains(group))
				    ownership.remove(ownership.indexOf(group));
		}
	}
}	
