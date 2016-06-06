/**
 * Represents a file in the FileServer which is listed in the FileList
 */
public class ShareFile implements java.io.Serializable, Comparable<ShareFile>
{
	private static final long serialVersionUID = -6699986336399821598L;
	private String group;   // Group to which this file belongs
	private String path;    // Path to the file on server
	private String owner;   // Owner of the file

    /**
     * Constructor which accepts the owner, group, and path
     *
     * @param _owner The owner
     * @param _group The group
     * @param _path The path
     */
	public ShareFile(String _owner, String _group, String _path)
    {
		group = _group;
		owner = _owner;
		path  = _path;
	}

    /**
     * Returns the path to this file
     *
     * @return The path
     */
	public String getPath()
	{
		return path;
	}

    /**
     * Returns the owner of this file
     *
     * @return The owner
     */
	public String getOwner()
	{
		return owner;
	}

    /**
     * Returns the group to which this file belongs
     *
     * @return The group
     */
	public String getGroup()
    {
		return group;
	}

    /**
     * Compares two files
     *
     * @param rhs The other file
     *
     * @return 0 if their paths are equal,
     *        -1 if this file's path is less than that file's path
     *         1 if this file's path is greater than that file's path
     */
	public int compareTo(ShareFile rhs)
    {
		if (path.compareTo(rhs.getPath()) == 0)return 0;
		else if (path.compareTo(rhs.getPath()) < 0) return -1;
		else return 1;
	}
}	
