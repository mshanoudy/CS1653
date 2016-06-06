import java.util.ArrayList;

/**
 * This class represents how messages are sent to and from servers
 */
public class Envelope implements java.io.Serializable
{
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;                                         // The message
	private ArrayList<Object> objContents = new ArrayList<>();  // Any objects that are sent with the message

    /**
     * Constructor which accepts a String as the message
     *
     * @param text The message
     */
	public Envelope(String text)
	{
		msg = text;
	}

    /**
     * Method which returns the message
     *
     * @return The message
     */
	public String getMessage()
	{
		return msg;
	}

    /**
     * Method which returns the objects enclosed in this envelope
     *
     * @return The enclosed objects
     */
	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}

    /**
     * This method attaches an object to the envelope
     *
     * @param object The object to be attached
     */
	public void addObject(Object object)
	{
		objContents.add(object);
	}
}
