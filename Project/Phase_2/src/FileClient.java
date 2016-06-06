import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * FileClient provides all the client functionality regarding the file server
 */
public class FileClient extends Client implements FileClientInterface
{
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
			output.writeObject(env);

            // Receive server response
		    env = (Envelope)input.readObject();
			if (env.getMessage().compareTo("OK") == 0)
				System.out.printf("File %s deleted successfully\n", filename);
			else
            {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		}
        catch (IOException | ClassNotFoundException e1)
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
                env.addObject(sourceFile);  // Add the filename on server
                env.addObject(token);       // Add the requester's token
                output.writeObject(env);    // Send message

                // Receive server response
                env = (Envelope)input.readObject();

                while (env.getMessage().compareTo("CHUNK") == 0)
                {// File is arriving in chunks
                    fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
                    System.out.printf(".");
                    env = new Envelope("DOWNLOADF");    // Tell the server to send next chunk
                    output.writeObject(env);            // Send message
                    env = (Envelope)input.readObject(); // Receive response
                }
                fos.close();

                if (env.getMessage().compareTo("EOF") == 0)
                {// Reached the end of file
                    fos.close();
                    System.out.printf("\nTransfer successful file %s\n", sourceFile);
                    env = new Envelope("OK"); // Tell the server it was a success
                    output.writeObject(env);  // Send message
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
        catch (ClassNotFoundException e1)
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
			 Envelope message,
                      e;

			 // Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token);    // Add requester's token
			 output.writeObject(message); // Send message

             // Receive response
			 e = (Envelope)input.readObject();
			 
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
			Envelope message,
                     env;

            // Tell the server to return the member list
            message = new Envelope("UPLOADF");
            message.addObject(destFile); // Add filename on server
            message.addObject(group);    // Add groupname
            message.addObject(token);    // Add requester's token
            output.writeObject(message); // Send message

            // Stream to local file
            FileInputStream fis = new FileInputStream(sourceFile);
            // Receive server response
            env = (Envelope)input.readObject();

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

                message.addObject(buf);            // Add the chunk
                message.addObject(new Integer(n)); // Not really sure why it's (new Integer(n)) instead of just (n)
                output.writeObject(message);       // Send message

                // Receive response
                env = (Envelope)input.readObject();
            } while (fis.available() > 0);

            // If server indicates success, return the member list
            if (env.getMessage().compareTo("READY") == 0)
            {
                // Tell server it has reached end of file
                message = new Envelope("EOF");
                output.writeObject(message); // Send message

                // Receive response
                env = (Envelope)input.readObject();
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
}

