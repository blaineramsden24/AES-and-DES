import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class DES {
    static Cipher cipher;

    public DES() throws Exception {
        cipher = Cipher.getInstance("DES");
    }

    public String encrypt(String message, SecretKey secretKey) throws Exception {
        byte[] plainMessageByte = message.getBytes();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedByte = cipher.doFinal(plainMessageByte);

        Base64.Encoder encoder = Base64.getEncoder();
        String encodedMessage = encoder.encodeToString(encryptedByte);

        return encodedMessage;
    }

    public String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(encryptedText);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);

        String decryptedText = new String(decryptedByte);

        return decryptedText;
    }

    public SecretKey generateRandomKey() throws NoSuchAlgorithmException{
        //Use java's key generator to produce a random key.
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        SecretKey secretKey = keyGenerator.generateKey();

        //print the key
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        //System.out.println(encodedKey);

        return secretKey;
    }

    public SecretKey generateKeyFromPassword(String password) throws Exception{

        //Get byte representation of password.
        //Note here you should ideally also use salt!
        byte[] passwordInBytes = (password).getBytes("UTF-8");

        //Use sha to generate a message digest of the password
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] key = sha.digest(passwordInBytes);

        //DES keys are only 64 bits (8 bytes) so take first 64 bits of digest.
        key = Arrays.copyOf(key, 8);

        //Generate secret key using
        SecretKeySpec secretKey = new SecretKeySpec(key, "DES");

        //print the key
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        //System.out.println(encodedKey);

        return secretKey;
    }
}
