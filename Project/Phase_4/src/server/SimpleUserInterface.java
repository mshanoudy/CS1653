package server;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignedObject;
import java.util.List;
import java.util.Scanner;

public class SimpleUserInterface extends Client
{
    public static int     gsPort;
    public static int     fsPort;
    public static String  gsName;
    public static String  fsName;

    public static  GroupClient  groupClient;
    public static  FileClient   fileClient;
    static         Scanner      scanner;

    /**
     * Main application method.
     * Contains the main application loop and handlers for user commands
     *
     * @param args Unused command line arguments
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException
    {
        String username;
        String password;

        if (args.length < 4)
        {// Check to see if server info was entered
            gsPort = 8765;
            fsPort = 4321;
            gsName = "localhost";
            fsName = "localhost";
        }
        else
        {// User entered server info
            gsPort = Integer.parseInt(args[0]);
            gsName = args[1];
            fsPort = Integer.parseInt(args[2]);
            fsName = args[3];
        }

        groupClient = new GroupClient();
        fileClient  = new FileClient();
        scanner     = new Scanner(System.in);    // To read in commands from user

        // Tries to connect and perform handshakes
        if (fileClient.connect(fsName, fsPort) && groupClient.connect(gsName, gsPort))
        {
            if (!groupClient.handshake())
            {
                System.out.println("Problem with GroupServer Handshake");
                System.exit(-1);
            }
            if (!fileClient.handshake(groupClient.getPublicKey()))
            {
                System.out.println("Problem with FileServer Handshake");
                System.exit(-1);
            }

            groupClient.setFileServerID(fileClient.getFileServerID());

            SignedObject token;

            boolean validLogin = false;
            // Loop login "screen"
            do
            {
                System.out.print("Please enter your username:");
                username = scanner.nextLine();
                System.out.print("Please enter your password:");
                password = scanner.nextLine();

                groupClient.setPassword(password);

                // check for token
                token = groupClient.getToken(username);
                if (token != null)
                    validLogin = true;
                else
                    System.out.println("Incorrect information...Please try again");
            } while(!validLogin);

            boolean connected = true;
            // Main application loop
            while (connected)
            {
                token = groupClient.getToken(username);

                UserToken yourToken = (UserToken)token.getObject();

                if (yourToken.getGroups().contains("ADMIN"))
                {// User is an ADMIN
                    displayAdminMenu();
                    switch (scanner.nextLine())
                    {
                        case "1":   // List Files
                            listFiles(token);
                            break;
                        case "2":   // Upload File
                            uploadFile(token);
                            break;
                        case "3":   // Download File
                            downloadFile(token);
                            break;
                        case "4":   // Delete File
                            deleteFile(token);
                            break;
                        case "5":   // Create Group
                            createGroup(token);
                            break;
                        case "6":   // Delete Group
                            deleteGroup(token);
                            break;
                        case "7":   // Add User
                            addUser(token);
                            break;
                        case "8":   // Remove User
                            removeUser(token);
                            break;
                        case "9":   // List Members
                            listMembers(token);
                            break;
                        case "0":   // Disconnect
                            fileClient.disconnect();
                            groupClient.disconnect();
                            connected = false;
                            break;
                        case "C":   // Create User
                            createUser(token);
                            break;
                        case "D":   // Delete User
                            deleteUser(token);
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
                            listFiles(token);
                            break;
                        case "2":   // Upload File
                            uploadFile(token);
                            break;
                        case "3":   // Download File
                            downloadFile(token);
                            break;
                        case "4":   // Delete File
                            deleteFile(token);
                            break;
                        case "5":   // Create Group
                            createGroup(token);
                            break;
                        case "6":   // Delete Group
                            deleteGroup(token);
                            break;
                        case "7":   // Add User
                            addUser(token);
                            break;
                        case "8":   // Remove User
                            removeUser(token);
                            break;
                        case "9":   // List Members
                            listMembers(token);
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
        else // connection to group or file server failed
        {
            System.out.println("Problem connecting to one of the servers...");
            System.out.println("Please make sure both servers are up and running correctly.");
            System.out.println("Shutting User Client down...");
            System.exit(-1);
        }
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
     * @param token The token of the requester
     */
    private static void listFiles(SignedObject token)
    {
        printLineBreaks(3);

        List<String> list = fileClient.listFiles(token);
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
     * @param token The token of the requester
     */
    private static void uploadFile(SignedObject token)
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
        SecretKey groupKey = (SecretKey)groupClient.getGroupKey(group, token).get(0);
        byte[] IV = (byte[])groupClient.getGroupKey(group, token).get(1);

        printLineBreaks(1);
        
        if (fileClient.upload(sourceFile, destFile, group, groupKey, IV, token))
            System.out.println("File uploaded successfully");
        else
            System.out.println("Error uploading file...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles downloading a file to the user
     *
     * @param token The token of the requester
     */
    private static void downloadFile(SignedObject token)
    {
        printLineBreaks(3);

        // Parameters for FileClient.download()
        String sourceFile, destFile, group;

        // Get parameters from user
        System.out.println("Please enter the filename used on the server");
        sourceFile = scanner.nextLine();
        System.out.println("Please enter the filename to use locally");
        destFile = scanner.nextLine();
        System.out.println("Please enter the group to share this file with");
        group = scanner.nextLine();

        SecretKey groupKey = (SecretKey)groupClient.getGroupKey(group, token).get(0);
        byte[] IV = (byte[])groupClient.getGroupKey(group, token).get(1);

        printLineBreaks(1);

        if (fileClient.download(sourceFile, destFile, groupKey, IV, token))
            System.out.println("File downloaded successfully");
        else
            System.out.println("Error downloading file...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles deleting a file on the server
     *
     * @param token The token of the requester
     */
    private static void deleteFile(SignedObject token)
    {
        printLineBreaks(3);

        // Parameter for FileClient.delete()
        String filename;

        // Get parameter from user
        System.out.println("Please enter the filename to delete");
        filename = scanner.nextLine();

        printLineBreaks(1);

        if (fileClient.delete(filename, token))
            System.out.println("File deleted successfully");
        else
            System.out.println("Error deleting file...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles creating a new group
     *
     * @param token The token of the requester
     */
    private static void createGroup(SignedObject token)
    {
        printLineBreaks(3);

        // Parameter for GroupClient.createGroup()
        String groupname;

        // Get parameter from user
        System.out.println("Please enter the name of the group to create");
        groupname = scanner.nextLine();

        printLineBreaks(1);

        if (groupClient.createGroup(groupname, token))
            System.out.println("Group created successfully");
        else
            System.out.println("Error creating group...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles deleting a group
     *
     * @param token The token of the requester
     */
    private static void deleteGroup(SignedObject token)
    {
        printLineBreaks(3);

        // Parameter for GroupClient.deleteGroup()
        String groupname;

        // Get parameter from user
        System.out.println("Please enter the name of the group to delete");
        groupname = scanner.nextLine();

        printLineBreaks(1);

        if (groupClient.deleteGroup(groupname, token))
            System.out.println("Group deleted successfully");
        else
            System.out.println("Error deleting group...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles adding a user to a group
     *
     * @param token The token of the requester
     */
    private static void addUser(SignedObject token)
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

        if (groupClient.addUserToGroup(username, groupname, token))
            System.out.println("User added to group successfully");
        else
            System.out.println("Error adding user to group...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles removing a user from a group
     *
     * @param token The token of the requester
     */
    private static void removeUser(SignedObject token)
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

        if (groupClient.deleteUserFromGroup(username, groupname, token))
            System.out.println("Removed the user from the group successfully");
        else
            System.out.println("Error removing user from group...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles displaying the members in a group
     *
     * @param token The token of the requester
     */
    private static void listMembers(SignedObject token)
    {
        printLineBreaks(3);

        // Parameter for GroupClient.listMembers()
        String groupname;

        // Get parameter from user
        System.out.println("Please enter the name of the group");
        groupname = scanner.nextLine();

        printLineBreaks(1);

        List<String> list = groupClient.listMembers(groupname, token);
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
     * @param token The token of the requester
     */
    private static void createUser(SignedObject token)
    {
        printLineBreaks(3);

        // Parameter for GroupClient.createUser()
        String username, password;

        // Get parameter from user
        System.out.println("Please enter the name of the user to create");
        username = scanner.nextLine();
        System.out.println("Please enter your password");
        password = scanner.nextLine();

        if (groupClient.createUser(username, password, token))
            System.out.println("User created successfully");
        else
            System.out.println("Error creating user...");

        printLineBreaks(3);
    }

    /**
     * Private method that handles deleting a user
     *
     * @param token The token of the requester
     */
    private static void deleteUser(SignedObject token)
    {
        printLineBreaks(3);

        // Parameter for GroupClient.deleteUser()
        String username;

        // Get parameter from user
        System.out.println("Please enter the name of the user to delete");
        username = scanner.nextLine();

        printLineBreaks(1);

        if (groupClient.deleteUser(username, token))
            System.out.println("User deleted successfully");
        else
            System.out.println("Error deleting user...");

        printLineBreaks(3);
    }
}
