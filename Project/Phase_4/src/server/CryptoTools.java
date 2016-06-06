package server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.Security;
import java.util.Arrays;

/**
 * Provides functionality for commonly used methods pertaining to the security measures used in this system
 */
public class CryptoTools
{
    private Cipher encryptionCipher; // Cipher for AES encryption
    private Cipher decryptionCipher; // Cipher for AES decryption
    private Mac    HMAC;             // Mac for HMAC
    private int    N;                // Increment value

    /**
     * Default Constructor
     * Only used in server-side handshake to decrypt envelope containing session keys
     */
    public CryptoTools()
    {
    }
    public CryptoTools(int N, SecretKey KS, byte[] IV, SecretKey KH) throws Exception
    {
        // Set provider to BouncyCaste
        Security.addProvider(new BouncyCastleProvider());

        // Set AES cipher details
        IvParameterSpec IVPS = new IvParameterSpec(IV);
        encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, KS, IVPS);
        decryptionCipher.init(Cipher.DECRYPT_MODE, KS, IVPS);

        // Set HMAC details
        HMAC = Mac.getInstance("HmacSHA1", "BC");
        HMAC.init(KH);

        // Set N
        this.N = N;
    }

    /**
     * Creates and returns an AES/CBC cipher for use with a CipherOutputStream or CipherInputStream in FileThread
     *
     * @param mode The mode of encryption
     * @param groupKey The symmetric key
     * @param IV The initialization vector
     *
     * @return The cipher if successful, null if not
     *
     * @throws Exception
     */
    public Cipher getFileCipher(String mode, SecretKey groupKey, byte[] IV) throws Exception
    {
        IvParameterSpec IVPS = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");

        switch (mode)
        {
            case "ENCRYPT":
                cipher.init(Cipher.ENCRYPT_MODE, groupKey, IVPS);
                break;
            case "DECRYPT":
                cipher.init(Cipher.DECRYPT_MODE, groupKey, IVPS);
                break;
            default:
                cipher = null;
                break;
        }

        return cipher;
    }

    /**
     * Converts an object into a byte array
     *
     * @param object The object
     *
     * @return byte array
     *
     * @throws Exception
     */
    public byte[] toByteArray(Object object) throws Exception
    {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream    o = new ObjectOutputStream(b);
        o.writeObject(object);

        return b.toByteArray();
    }

    /**
     * Converts a byte array to an object
     *
     * @param object The byte array
     *
     * @return The object
     *
     * @throws Exception
     */
    public Object fromByteArray(byte[] object) throws Exception
    {
        ByteArrayInputStream b = new ByteArrayInputStream(object);
        ObjectInputStream    o = new ObjectInputStream(b);

        return o.readObject();
    }

    /**
     * Encrypts an object using AES
     *
     * @param object The object
     *
     * @return cipher text
     *
     * @throws Exception
     */
    public byte[] encrypt(Object object) throws Exception
    {
        return encryptionCipher.doFinal(toByteArray(object));
    }

    /**
     * Decrypts an object using AES
     *
     * @param object The cipher text
     *
     * @return The object
     *
     * @throws Exception
     */
    public Object decrypt(byte[] object) throws Exception
    {
        return fromByteArray(decryptionCipher.doFinal(object));
    }

    /**
     * Gets the digest of an object generated using HMAC
     *
     * @param object The object
     *
     * @return The digest
     *
     * @throws Exception
     */
    public byte[] getDigest(Object object) throws Exception
    {
        return HMAC.doFinal(toByteArray(object));
    }

    /**
     * Verifies whether two digests match
     *
     * @param thisDigest first digest to compare
     * @param thatDigest second digest to compare
     *
     * @return true is they match, false otherwise
     */
    public boolean verifyDigest(byte[] thisDigest, byte[] thatDigest)
    {
        return Arrays.equals(thisDigest, thatDigest);
    }

    /**
     * Getter method for N
     *
     * @return N
     */
    public int getN()
    {
        return N;
    }

    /**
     * Verifies is N is correct
     *
     * @param value N to be verified
     *
     * @return true is N was incremented, false otherwise
     */
    public boolean verifyN(int value)
    {
        return value == (N + 1);
    }

    /**
     * Increments N
     */
    public void incrementN()
    {
        N++;
    }

    /**
     * Verifies both the HMAC digest and the increment value N
     *
     * @param envelope The message to be verified
     * @param digest The digest of said message
     *
     * @return true if verified, false otherwise
     *
     * @throws Exception
     */
    public boolean verifyMessage(Envelope envelope, byte[] digest) throws Exception
    {
        return verifyDigest(getDigest(envelope), digest) && verifyN((int) envelope.getObjContents().get(0));
    }
}
