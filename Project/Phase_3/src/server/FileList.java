package server;

import java.util.*;

/**
 * This list represents the files on the server
 */
public class FileList implements java.io.Serializable
{
	private static final long serialVersionUID = -8911161283900260136L;
	private ArrayList<ShareFile> list;  // list of files

    /**
     * Default constructor, creates empty list
     */
	public FileList()
	{
		list = new ArrayList<>();
	}

    /**
     * Adds a file to the FileList
     *
     * @param owner The owner of the file
     * @param group The group to which this file belongs
     * @param path The path to the file
     */
	public synchronized void addFile(String owner, String group, String path)
	{
		ShareFile newFile = new ShareFile(owner, group, path);
		list.add(newFile);
	}

    /**
     * Removes file from FileList
     *
     * @param path The path to the file
     */
	public synchronized void removeFile(String path)
	{
		for (int i = 0; i < list.size(); i++)
			if (list.get(i).getPath().compareTo(path) == 0)
				list.remove(i);
	}

    /**
     * Checks if file exists in FileList
     *
     * @param path The path to the file
     * @return true if present, false otherwise
     */
	public synchronized boolean checkFile(String path)
	{
        for (ShareFile aList : list)
            if (aList.getPath().compareTo(path) == 0)
                return true;
		return false;
	}

    /**
     * Returns list of files in FileList
     *
     * @return The list of files
     */
	public synchronized ArrayList<ShareFile> getFiles()
	{
		Collections.sort(list);
		return list;			
	}

    /**
     * Returns the file specified
     *
     * @param path The path to the file
     * @return The file
     */
	public synchronized ShareFile getFile(String path)
	{
        for (ShareFile aList : list)
            if (aList.getPath().compareTo(path) == 0)
                return aList;
		return null;
	}
}	
