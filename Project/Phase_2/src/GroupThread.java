import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;

/**
 * This thread does all the work. It communicates with the client through Envelopes.
 */
public class GroupThread extends Thread 
{
	private final Socket      socket;   // The socket
	private       GroupServer my_gs;    // The GroupServer

    /**
     * Constructor which accepts the socket and GroupServer
     *
     * @param _socket The socket
     * @param _gs The GroupServer
     */
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs  = _gs;
	}

    /**
     * Method that runs this thread.
     * Contains all the handlers for messages this server accepts from client,
     * which are outlined in GroupClientInterface.java
     */
	public void run()
	{
		boolean proceed = true;

		try
		{
			// Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " ***");
			final ObjectInputStream  input  = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{// Listen for messages from client
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;

                // TODO: Maybe change this to a switch statement?
                /* Client wants a token */
				if (message.getMessage().equals("GET"))
				{
                    // Get the username
					String username = (String)message.getObjContents().get(0);

					if (username == null)
					{// If user is null, send back fail and a null token
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{// Create a token for the client
						UserToken yourToken = createToken(username);

						// Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						output.writeObject(response);
					}
				}
                /* Client wants to create a user */
				else if (message.getMessage().equals("CUSER"))
				{
                    // Check to make sure both parameters are passed
					if (message.getObjContents().size() < 2)
						response = new Envelope("FAIL");
					else
					{
						response = new Envelope("FAIL");

                        // Check to make sure both parameters != null
						if (message.getObjContents().get(0) != null)     // username
							if (message.getObjContents().get(1) != null) // token
							{// Extract the username and token
								String    username  = (String)message.getObjContents().get(0);
								UserToken yourToken = (UserToken)message.getObjContents().get(1);

                                // If user is created, change response to OK
								if (createUser(username, yourToken))
									response = new Envelope("OK");
							}
					}
                    // Send response
					output.writeObject(response);
				}
                /* Client wants to delete a user */
				else if (message.getMessage().equals("DUSER"))
				{
                    // Check to make sure both parameters are passed
					if (message.getObjContents().size() < 2)
						response = new Envelope("FAIL");
					else
					{
						response = new Envelope("FAIL");

                        // Check to make sure both parameters != null
						if (message.getObjContents().get(0) != null)
							if (message.getObjContents().get(1) != null)
							{// Extract the username and token
								String    username  = (String)message.getObjContents().get(0);
								UserToken yourToken = (UserToken)message.getObjContents().get(1);

                                // If user is deleted, change response to OK
								if (deleteUser(username, yourToken))
									response = new Envelope("OK");
							}
					}
					// Send response
					output.writeObject(response);
				}
                /* Client wants to create a group */
				else if (message.getMessage().equals("CGROUP"))
				{
                    // Check to make sure both parameters are passed
                    if (message.getObjContents().size() < 2)
                        response = new Envelope("FAIL");
                    else
                    {
                        response = new Envelope("FAIL");

                        // Check to make sure both parameters != null
                        if (message.getObjContents().get(0) != null)
                            if (message.getObjContents().get(1) != null)
                            {// Extract groupname and token
                                String    groupname = (String)message.getObjContents().get(0);
                                UserToken yourToken = (UserToken)message.getObjContents().get(1);

                                // If group is created, change response to OK
                                if (createGroup(groupname, yourToken))
                                    response = new Envelope("OK");
                            }
                    }
                    // Send response
                    output.writeObject(response);
				}
                /* Client wants to delete a group */
				else if (message.getMessage().equals("DGROUP"))
				{
                    // Check to make sure both parameters are passed
                    if (message.getObjContents().size() < 2)
                        response = new Envelope("FAIL");
                    else
                    {
                        response = new Envelope("FAIL");

                        // Check to make sure both parameters != null
                        if (message.getObjContents().get(0) != null)
                            if (message.getObjContents().get(1) != null)
                            {// Extract groupname and token
                                String    groupname = (String)message.getObjContents().get(0);
                                UserToken yourToken = (UserToken)message.getObjContents().get(1);

                                // If group is created, change response to OK
                                if (deleteGroup(groupname, yourToken))
                                    response = new Envelope("OK");
                            }
                    }
                    // Send response
                    output.writeObject(response);
				}
                /* Client wants a list of members in a group */
				else if (message.getMessage().equals("LMEMBERS"))
				{
                    // Check to make sure both parameters are passed
                    if (message.getObjContents().size() < 2)
                        response = new Envelope("FAIL");
                    else
                    {
                        response = new Envelope("FAIL");

                        // Check to make sure both parameters != null
                        if (message.getObjContents().get(0) != null)
                            if (message.getObjContents().get(1) != null)
                            {// Extract groupname and token
                                String    groupname = (String)message.getObjContents().get(0);
                                UserToken yourToken = (UserToken)message.getObjContents().get(1);

                                // If member list was returned, change response to OK and send list
                                List<String> temp = listMembers(groupname, yourToken);
                                if (temp != null)
                                {
                                    response = new Envelope("OK");
                                    response.addObject(temp);
                                }
                            }
                    }
                    // Send response
                    output.writeObject(response);
				}
                /* Client wants to add user to a group */
				else if (message.getMessage().equals("AUSERTOGROUP"))
				{
                    // Check to make sure all parameters are passed
                    if (message.getObjContents().size() < 3)
                        response = new Envelope("FAIL");
                    else
                    {
                        response = new Envelope("FAIL");

                        // Check to make sure all parameters != null
                        if (message.getObjContents().get(0) != null)
                            if (message.getObjContents().get(1) != null)
                                if (message.getObjContents().get(2) != null)
                                {// Extract parameters
                                    String    username  = (String)message.getObjContents().get(0);
                                    String    groupname = (String)message.getObjContents().get(1);
                                    UserToken yourToken = (UserToken)message.getObjContents().get(2);

                                    // If user is added to group, change response to OK
                                    if (addUserToGroup(username, groupname, yourToken))
                                        response = new Envelope("OK");
                                }
                    }
                    // Send response
                    output.writeObject(response);
				}
                /* Client wants to remove user from a group */
				else if (message.getMessage().equals("RUSERFROMGROUP"))
				{
                    // Check to make sure all parameters are passed
                    if (message.getObjContents().size() < 3)
                        response = new Envelope("FAIL");
                    else
                    {
                        response = new Envelope("FAIL");

                        // Check to make sure all parameters != null
                        if (message.getObjContents().get(0) != null)
                            if (message.getObjContents().get(1) != null)
                                if (message.getObjContents().get(2) != null)
                                {// Extract parameters
                                    String    username  = (String)message.getObjContents().get(0);
                                    String    groupname = (String)message.getObjContents().get(1);
                                    UserToken yourToken = (UserToken)message.getObjContents().get(2);

                                    // If user is added to group, change response to OK
                                    if (deleteUserFromGroup(username, groupname, yourToken))
                                        response = new Envelope("OK");
                                }
                    }
                    // Send response
                    output.writeObject(response);
				}
                /* Client wants to disconnect */
				else if (message.getMessage().equals("DISCONNECT"))
				{
					socket.close();  // Close the socket
					proceed = false; // End this communication loop
				}
				else
				{
					response = new Envelope("FAIL"); // Server does not understand client request
					output.writeObject(response);
				}
			} while (proceed);
		}
		catch (Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

    /**
     * Private method used to create a token
     * @param username The user requesting a token
     * @return The user's token or null if the user does not exist
     */
	private UserToken createToken(String username) 
	{
		// Check that user exists
        // Issue a new token with server's name, user's name, and user's groups
        if (my_gs.userList.checkUser(username))
            return new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
		else // user does not exist
			return null;
	}

    /**
     * Private method used to create a user
     * @param username The user to be created
     * @param yourToken The token of the requester
     * @return true if the user was created, false otherwise
     */
	private boolean createUser(String username, UserToken yourToken)
	{
        // Get username of the requester
		String requester = yourToken.getSubject();
		
		// Check if requester exists
		if (my_gs.userList.checkUser(requester))
		{
			// Get the requester's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			// requester needs to be an administrator
			if (temp.contains("ADMIN"))
			{// Check if user being created already exists
				if (my_gs.userList.checkUser(username))
					return false; // user already exists
				else
                {// Add user to GroupServer
					my_gs.userList.addUser(username);
					return true;
				}
			}
			else // requester is not an admin
				return false;
		}
		else // requester does not exist
			return false;
	}

    /**
     * Private method used to delete a user
     * TODO: Make sure the ADMIN user cannot delete itself
     * @param username The user to be deleted
     * @param yourToken The token of the requester
     * @return true if the user was deleted, false otherwise
     */
	private boolean deleteUser(String username, UserToken yourToken)
	{
        // Get username of requester
		String requester = yourToken.getSubject();
		
		// Check if requester exists
		if (my_gs.userList.checkUser(requester))
		{
            // Get the requester's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			// requester needs to be an administer
			if (temp.contains("ADMIN"))
			{// Check if user exists
				if (my_gs.userList.checkUser(username))
				{
					// User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<>(); // <-- This is a Java 7 thing
					// This loop will produce a hard copy of the list of groups this user belongs
					for (int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					
					// Delete the user from the groups
					// If user is the owner, removeMember will automatically delete group!
                    for (String dFG : deleteFromGroups)
                        my_gs.groupList.removeMember(username, dFG);

					// If groups are owned, they must be deleted and removed from any member user's group list
					ArrayList<String> deleteOwnedGroup = new ArrayList<>();
					// This loop will make a hard copy of the user's ownership list
					for (int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));

					// Delete owned groups
                    // TODO: MAKE SURE THIS WORKS!
					for (int index = 0; index < deleteOwnedGroup.size(); index++)
						// Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));

					// Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else // User does not exist
					return false;
			}
			else // requester is not an administer
				return false;
		}
		else // requester does not exist
			return false;
	}

    /**
     * Private method used to create a group
     * @param groupname The group to be created
     * @param yourToken The token of the requester
     * @return true if the group was created, false otherwise
     */
    private boolean createGroup(String groupname, UserToken yourToken)
    {
        // Get username of the requester
        String requester = yourToken.getSubject();

        // Check if requester exists
        if (my_gs.userList.checkUser(requester))
        {// Create Group
            // Add group to GroupList and set requester as owner
            my_gs.groupList.addGroup(groupname);
            my_gs.groupList.addMember(requester, groupname);
            my_gs.groupList.setOwner(requester, groupname);

            // Add group to requester's groups and ownership list
            my_gs.userList.addOwnership(requester, groupname);
            my_gs.userList.addGroup(requester, groupname);
            return true;
        }
        else // requester does not exist
            return false;
    }

    /**
     * Private method used to delete groups
     * @param groupname The group to be deleted
     * @param yourToken The token of the requester
     * @return true if the group was deleted, false otherwise
     */
    private boolean deleteGroup(String groupname, UserToken yourToken)
    {
        // Get username of requester
        String requester = yourToken.getSubject();

        // Check if requester exists
        if (my_gs.userList.checkUser(requester))
        {
            // Get the requester's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            // Check if group exists
            if (my_gs.groupList.checkGroup(groupname))
            {// The requester needs to be owner or admin
                if (my_gs.groupList.getGroupOwner(groupname).equals(requester) || temp.contains("ADMIN"))
                {
                    // Members need to have group removed from their groups list
                    ArrayList<String> deleteFromGroup = new ArrayList<>();
                    // This loop will produce a hard copy of the list of members in the group
                    for (int index = 0; index < my_gs.groupList.getGroupMembers(groupname).size(); index++)
                        deleteFromGroup.add(my_gs.groupList.getGroupMembers(groupname).get(index));

                    // Delete group from members' list
                    for (String username : deleteFromGroup)
                        my_gs.userList.removeGroup(username, groupname);
                    // If requester is owner, remove ownership
                    if (my_gs.groupList.getGroupOwner(groupname).equals(requester))
                        my_gs.userList.removeOwnership(requester, groupname);

                    // Delete the group from GroupList
                    my_gs.groupList.deleteGroup(groupname);

                    return true;
                }
                else // group does not exist
                    return false;
            }
            else // requester does not have permission
                return false;
        }
        else // requester does not exist
            return false;
    }

    /**
     * Private method that returns the list of all users that are currently members of the group
     * @param groupname The group
     * @param yourToken The token of the requester
     * @return The list of all users that are currently members of the group, null otherwise
     */
    private List<String> listMembers(String groupname, UserToken yourToken)
    {
        // Get username of requester
        String requester = yourToken.getSubject();

        // Check if requester exists
        if (my_gs.userList.checkUser(requester))
        {
            // Get the requester's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            // Check if group exist
            if (my_gs.groupList.checkGroup(groupname))
            {// The requester needs to be owner or admin
                if (my_gs.groupList.getGroupOwner(groupname).equals(requester) || temp.contains("ADMIN"))
                    return my_gs.groupList.getGroupMembers(groupname);
                else // group does not exist
                    return null;
            }
            else // requester does not have permission
                return null;
        }
        else // requester does not exist
            return null;
    }

    /**
     * Private method that adds a user to a group
     * @param username The user to be added
     * @param groupname The group
     * @param yourToken The token of the requester
     * @return true is user was added to group, false otherwise
     */
    private boolean addUserToGroup(String username, String groupname, UserToken yourToken)
    {
        // Get username of requester
        String requester = yourToken.getSubject();

        // Check if requester exists
        if (my_gs.userList.checkUser(requester))
        {
            // Get the requester's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            // The requester needs to be owner or admin
            if (my_gs.groupList.getGroupOwner(groupname).equals(requester) || temp.contains("ADMIN"))
            {// Check if group exists
                if (my_gs.groupList.checkGroup(groupname))
                {// Check if user exists
                    if (my_gs.userList.checkUser(username))
                    {
                        // Add user to the group's members in GroupList
                        my_gs.groupList.addMember(username, groupname);
                        // Add group to user's group list in UserList
                        my_gs.userList.addGroup(username, groupname);

                        return true;
                    }
                    else // user does not exist
                        return false;
                }
                else // group does not exist
                    return false;
            }
            else // requester does not have permission
                return false;
        }
        else // requester does not exist
            return false;
    }

    /**
     * Private method that deletes a user from a group
     * @param username The user to be deleted
     * @param groupname The group
     * @param yourToken The token of the requester
     * @return true if user was deleted from group, false otherwise
     */
    private boolean deleteUserFromGroup(String username, String groupname, UserToken yourToken)
    {
        // Get username of requester
        String requester = yourToken.getSubject();

        // Check if requester exists
        if (my_gs.userList.checkUser(requester))
        {
            // Get the requester's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            // The requester needs to be owner or admin
            if (my_gs.groupList.getGroupOwner(groupname).equals(requester) || temp.contains("ADMIN"))
            {// Check if group exists
                if (my_gs.groupList.checkGroup(groupname))
                {// Check if user exists
                    if (my_gs.userList.checkUser(username))
                    {
                        // Remove user from group's members in GroupList
                        my_gs.groupList.removeMember(username, groupname);
                        // Remove group from user's group list in UserList
                        my_gs.userList.removeGroup(username, groupname);

                        return true;
                    }
                    else // user does not exist
                        return false;
                }
                else // group does not exist
                    return false;
            }
            else // requester does not have permission
                return false;
        }
        else // requester does not exist
            return false;
    }
}
