import java.io.Serializable;
import java.util.List;

/**
 * Implementation of the UserToken interface.
 *
 * The UserToken interface plays an important role, as it represents the binding between a user
 * and the groups that he or she belongs to. The UserToken interface is the only connection between
 * the group client/server and the file client/server.
 */
public class Token implements UserToken, Serializable
{
    private String        issuer;     // Issuer of this token
    private String        subject;    // Subject of this token
    private List<String>  groups;     // List of group memberships encoded in this token

    /**
     * Constructor for the Token class
     *
     * @param issuer Issuer of this token
     * @param subject Subject of this token
     * @param groups List of group memberships encoded in this token
     */
    public Token(String issuer, String subject, List<String> groups)
    {
        this.issuer  = issuer;
        this.subject = subject;
        this.groups  = groups;
    }

    /**
     * This method returns a string describing the issuer of this token. This string identifies
     * the group server that created this token. For instance, if "Alice" requests a token from
     * group server "Server1", this method will return the string "Server1".
     *
     * @return The issuer of this token
     */
    public String getIssuer()
    {
        return issuer;
    }

    /**
     * This method returns a string indicating the name of the subject of this token. For
     * instance, if "Alice" requests a token rom the group server "Server1", this method will
     * return the string "Alice".
     *
     * @return The subject of this token
     */
    public String getSubject()
    {
        return subject;
    }

    /**
     * This method extracts the list of groups that the owner of this token has access to. For
     * instance, if "Alice" is a member of the groups "G1" and "G2", defined at the group server
     * "Server1", this method will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     */
    public List<String> getGroups()
    {
        return groups;
    }
}
