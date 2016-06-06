import java.util.List;
import java.util.Scanner;

/**
 * Simple user client to interact with the file sharing system via the Group and File Servers
 */
public class SimpleUserClient extends Client
{
    // TODO: Add support for entering server ports on startup
    public static final int     GROUP_SERVER_DEFAULT_PORT = 8765;
    public static final int     FILE_SERVER_DEFAULT_PORT  = 4321;
    public static final String  GROUP_SERVER_DEFAULT_NAME = "localhost";
    public static final String  FILE_SERVER_DEFAULT_NAME  = "localhost";

    // TODO: These may need to be changed from static if they cause bugs, we'll see
    static FileClient  fileClient;  // FileClient to interact with the FileServer
    static GroupClient groupClient; // GroupClient to interact with the GroupServer
    static Scanner     scanner;     // To read in commands from user


    /**
     * Main application method.
     * Contains the main application loop and handlers for user commands
     *
     * @param args Unused command line arguments
     */
    public static void main(String[] args)
    {
        scanner     = new Scanner(System.in);
        fileClient  = new FileClient();
        groupClient = new GroupClient();

        try
        {// Connect to the Group and File servers
            fileClient.connect(FILE_SERVER_DEFAULT_NAME, FILE_SERVER_DEFAULT_PORT);
            groupClient.connect(GROUP_SERVER_DEFAULT_NAME, GROUP_SERVER_DEFAULT_PORT);
        }
        catch (Exception e)
        {// Problem connecting to the servers, shut this client down
            System.out.println("Problem connecting to one of the servers...");
            System.out.println("Please make sure both servers are up and running correctly.");
            System.out.println("Shutting User Client down...");
            System.exit(-1);
        }

        String    requester;    // The requester using this client
        UserToken yourToken;    // The requester token
        System.out.println("Welcome to the Simple User Client");
        do
        {// Get the username of the requester
            System.out.print("Please enter your username: ");
            requester = scanner.nextLine();

            // Get token for user, if no token is returned user does not exist
            yourToken = groupClient.getToken(requester);

            if      (yourToken != null) break;                  // Exit the loop
            else if (requester.equals("EXIT")) System.exit(-1); // Quit the application
            else    System.out.println("Username not found!\nPlease try again or enter EXIT to quit...");
        } while (true);

        System.out.println("Hello, " + requester + "!");
        System.out.println("What would you liked to don't\n");

        boolean connected = true;

        // Main application loop
        while (connected)
        {// Only runs if still connected to file and group servers
            // Disconnect and reconnect every time -- fix for a bug with the token update
            fileClient.disconnect();
            groupClient.disconnect();
            fileClient.connect(FILE_SERVER_DEFAULT_NAME, FILE_SERVER_DEFAULT_PORT);
            groupClient.connect(GROUP_SERVER_DEFAULT_NAME, GROUP_SERVER_DEFAULT_PORT);

            // Update the token
            yourToken = groupClient.getToken(requester);

            if (yourToken.getGroups().contains("ADMIN"))
            {// User is an ADMIN
                displayAdminMenu();
                switch (scanner.nextLine())
                {
                    case "1":   // List Files
                        listFiles(yourToken);
                        break;
                    case "2":   // Upload File
                        uploadFile(yourToken);
                        break;
                    case "3":   // Download File
                        downloadFile(yourToken);
                        break;
                    case "4":   // Delete File
                        deleteFile(yourToken);
                        break;
                    case "5":   // Create Group
                        createGroup(yourToken);
                        break;
                    case "6":   // Delete Group
                        deleteGroup(yourToken);
                        break;
                    case "7":   // Add User
                        addUser(yourToken);
                        break;
                    case "8":   // Remove User
                        removeUser(yourToken);
                        break;
                    case "9":   // List Members
                        listMembers(yourToken);
                        break;
                    case "0":   // Disconnect
                        fileClient.disconnect();
                        groupClient.disconnect();
                        connected = false;
                        break;
                    case "C":   // Create User
                        createUser(yourToken);
                        break;
                    case "D":   // Delete User
                        deleteUser(yourToken);
                        break;
                    default:
                        System.out.println("Invalid command entered");
                }
            }
            else
            {// Normal User
                displayMainMenu();
                switch (scanner.nextLine())
                {
                    case "1":   // List Files
                        listFiles(yourToken);
                        break;
                    case "2":   // Upload File
                        uploadFile(yourToken);
                        break;
                    case "3":   // Download File
                        downloadFile(yourToken);
                        break;
                    case "4":   // Delete File
                        deleteFile(yourToken);
                        break;
                    case "5":   // Create Group
                        createGroup(yourToken);
                        break;
                    case "6":   // Delete Group
                        deleteGroup(yourToken);
                        break;
                    case "7":   // Add User
                        addUser(yourToken);
                        break;
                    case "8":   // Remove User
                        removeUser(yourToken);
                        break;
                    case "9":   // List Members
                        listMembers(yourToken);
                        break;
                    case "0":   // Disconnect
                        fileClient.disconnect();
                        groupClient.disconnect();
                        connected = false;
                        break;
                    default:
                        System.out.println("Invalid command entered");
                }
            }
        }

        System.out.println("Disconnected from servers");
        System.out.println("Shutting down client...");
        System.exit(0);
    }

    /**
     * Prints the main menu
     */
    private static void displayMainMenu()
    {
        System.out.println("Main Menu:");
        System.out.println("1: List my files on the server");
        System.out.println("2: Upload a file to the server");
        System.out.println("3. Download a file from the server");
        System.out.println("4: Delete a file from the server");
        System.out.println("5: Create a new group on the server");
        System.out.println("6: Delete a group on the server");
        System.out.println("7: Add a user to a group");
        System.out.println("8: Remove a user from a group");
        System.out.println("9: List the members of a group");
        System.out.println("0: Disconnect from the client");
    }

    /**
     * Prints the main menu plus ADMIN options
     */
    private static void displayAdminMenu()
    {
        System.out.print("ADMIN ");
        displayMainMenu();
        System.out.println("C: Create user");
        System.out.println("D: Delete user");
    }

    /**
     * Prints line breaks
     *
     * @param n The number of linebreaks
     */
    private static void printLineBreaks(int n)
    {
        for (int i = 0; i < n; i++)
            System.out.println("");
    }

    /**
     * Private method that handles listing a user's files
     *
     * @param yourToken The token of the requester
     */
    private static void listFiles(UserToken yourToken)
    {
        printLineBreaks(3);

        List<String> list = fileClient.listFiles(yourToken);
        if (list.isEmpty())
            System.out.println("No files to list");
        else // Print the list
            for (String file : list)
                System.out.println(file);

        printLineBreaks(3);
    }

    /**
     * Private method that handles upload a user's file
     *
     * @param yourToken The token of the requester
     */
    private static void uploadFile(UserToken yourToken)
    {
        printLineBreaks(3);

        // Parameters for FileClient.upload()
        String sourceFile, destFile, group;

        // Get the parameters from user
        System.out.println("Please enter the path to the local file to upload");
        sourceFile = scanner.nextLine();
        System.out.println("Please enter the filename you wish to use on the server");
        destFile   = scanner.nextLine();
        System.out.println("Please enter the group to share this file with");
        group      = scanner.nextLine();

        printLineBreaks(1);

        if (fileClient.upload(sourceFile, destFile, group, yourToken))
            System.out.println("File uploaded successfully");
        else
            System.out.println("Error uploading file...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles downloading a file to the user
     *
     * @param yourToken The token of the requester
     */
    private static void downloadFile(UserToken yourToken)
    {
        printLineBreaks(3);

        // Parameters for FileClient.download()
        String sourceFile, destFile;

        // Get parameters from user
        System.out.println("Please enter the filename used on the server");
        sourceFile = scanner.nextLine();
        System.out.println("Please enter the filename to use locally");
        destFile = scanner.nextLine();

        printLineBreaks(1);

        if (fileClient.download(sourceFile, destFile, yourToken))
            System.out.println("File downloaded successfully");
        else
            System.out.println("Error downloading file...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles deleting a file on the server
     *
     * @param yourToken The token of the requester
     */
    private static void deleteFile(UserToken yourToken)
    {
        printLineBreaks(3);

        // Parameter for FileClient.delete()
        String filename;

        // Get parameter from user
        System.out.println("Please enter the filename to delete");
        filename = scanner.nextLine();

        printLineBreaks(1);

        if (fileClient.delete(filename, yourToken))
            System.out.println("File deleted successfully");
        else
            System.out.println("Error deleting file...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles creating a new group
     *
     * @param yourToken The token of the requester
     */
    private static void createGroup(UserToken yourToken)
    {
        printLineBreaks(3);

        // Parameter for GroupClient.createGroup()
        String groupname;

        // Get parameter from user
        System.out.println("Please enter the name of the group to create");
        groupname = scanner.nextLine();

        printLineBreaks(1);

        if (groupClient.createGroup(groupname, yourToken))
            System.out.println("Group created successfully");
        else
            System.out.println("Error creating group...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles deleting a group
     *
     * @param yourToken The token of the requester
     */
    private static void deleteGroup(UserToken yourToken)
    {
        printLineBreaks(3);

        // Parameter for GroupClient.deleteGroup()
        String groupname;

        // Get parameter from user
        System.out.println("Please enter the name of the group to delete");
        groupname = scanner.nextLine();

        printLineBreaks(1);

        if (groupClient.deleteGroup(groupname, yourToken))
            System.out.println("Group deleted successfully");
        else
            System.out.println("Error deleting group...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles adding a user to a group
     *
     * @param yourToken The token of the requester
     */
    private static void addUser(UserToken yourToken)
    {
        printLineBreaks(3);

        // Parameters for GroupClient.addUserToGroup()
        String username, groupname;

        // Get parameter from user
        System.out.println("Please enter the name of the user to add");
        username  = scanner.nextLine();
        System.out.println("Please enter the name of the group");
        groupname = scanner.nextLine();

        printLineBreaks(1);

        if (groupClient.addUserToGroup(username, groupname, yourToken))
            System.out.println("User added to group successfully");
        else
            System.out.println("Error adding user to group...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles removing a user from a group
     *
     * @param yourToken The token of the requester
     */
    private static void removeUser(UserToken yourToken)
    {
        printLineBreaks(3);

        // Parameters for GroupClient.deleteUserFromGroup()
        String username, groupname;

        // Get parameter from user
        System.out.println("Please enter the name of the user to remove");
        username = scanner.nextLine();
        System.out.println("Please enter the name of the group");
        groupname = scanner.nextLine();

        printLineBreaks(1);

        if (groupClient.deleteUserFromGroup(username, groupname, yourToken))
            System.out.println("Removed the user from the group successfully");
        else
            System.out.println("Error removing user from group...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles displaying the members in a group
     *
     * @param yourToken The token of the requester
     */
    private static void listMembers(UserToken yourToken)
    {
        printLineBreaks(3);

        // Parameter for GroupClient.listMembers()
        String groupname;

        // Get parameter from user
        System.out.println("Please enter the name of the group");
        groupname = scanner.nextLine();

        printLineBreaks(1);

        List<String> list = groupClient.listMembers(groupname, yourToken);
        if (list == null)
            System.out.println("No group members to list");
        else // Print the list
            for (String member : list)
                System.out.println(member);

        printLineBreaks(3);
    }

    /**
     * Private method that handles creating a new user
     *
     * @param yourToken The token of the requester
     */
    private static void createUser(UserToken yourToken)
    {
        printLineBreaks(3);

        // Parameter for GroupClient.createUser()
        String username;

        // Get parameter from user
        System.out.println("Please enter the name of the user to create");
        username = scanner.nextLine();

        printLineBreaks(1);

        if (groupClient.createUser(username, yourToken))
            System.out.println("User created successfully");
        else
            System.out.println("Error creating user...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles deleting a user
     *
     * @param yourToken The token of the requester
     */
    private static void deleteUser(UserToken yourToken)
    {
        printLineBreaks(3);

        // Parameter for GroupClient.deleteUser()
        String username;

        // Get parameter from user
        System.out.println("Please enter the name of the user to delete");
        username = scanner.nextLine();

        printLineBreaks(1);

        if (groupClient.deleteUser(username, yourToken))
            System.out.println("User deleted successfully");
        else
            System.out.println("Error deleting user...");

        printLineBreaks(3);
    }
}
