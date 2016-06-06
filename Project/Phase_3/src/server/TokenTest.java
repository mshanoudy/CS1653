package server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.util.ArrayList;

public class TokenTest
{
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException, SignatureException, ClassNotFoundException
    {
        UserToken token = new Token("server", "admin", new ArrayList<String>());
        Security.addProvider(new BouncyCastleProvider());

        // This shit is done in the GroupServer
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair    keyPair    = keyPairGenerator.generateKeyPair();
        PublicKey  publicKey  = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // This would be done in the Token constructor (need to pass privateKey to it)
        Signature  signature  = Signature.getInstance("SHA1withRSA", "BC");
        signature.initSign(privateKey);
        // Need to serialize the token
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream    o = new ObjectOutputStream(b);
        o.writeObject(token);

        // This would be done in the createToken method in GroupThread
        SignedObject signedToken = new SignedObject(b.toByteArray(), privateKey, signature);

        // Verification
        if (signedToken.verify(publicKey, signature))
            System.out.println("Verify Worked");

        // Deserialization
        ByteArrayInputStream bis = new ByteArrayInputStream((byte[]) signedToken.getObject());
        ObjectInputStream    ois = new ObjectInputStream(bis);

        UserToken temp = (UserToken)ois.readObject();

        // Checking to make sure there was no forgery/tampering
        if (temp.getSubject().equals(token.getSubject()))
            System.out.println("Tokens match");
    }
}
