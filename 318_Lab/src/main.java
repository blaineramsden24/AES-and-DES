import javax.crypto.SecretKey;

public class main {

    public static void main(String args[]) throws Exception {

        //AES
        AES aes = new AES();

        //Not random Key
        String secretMessage = "Secret Message!";
        SecretKey secretKey = aes.generateKeyFromPassword("Secret Message");
        String encryptedMessage = aes.encrypt(secretMessage, secretKey);

        System.out.println("AES ");
        System.out.println("Not Random: ");
        System.out.println("Encrypted Message: " + encryptedMessage);
        System.out.println("Decrypted Message: " + aes.decrypt(encryptedMessage, secretKey) + "\n") ;

        //Random Key
        SecretKey secretKeyRand = aes.generateRandomKey();
        String encryptedMessageRand = aes.encrypt(secretMessage, secretKeyRand);

        System.out.println("Random: ");
        System.out.println("Encrypted Message: " + encryptedMessageRand);
        System.out.println("Decrypted Message: " + aes.decrypt(encryptedMessageRand, secretKeyRand)) ;

        //DES

        DES des = new DES();

        //Not random Key
        String secretMessageD = "Secret Message!";
        SecretKey secretKeyD = des.generateKeyFromPassword("Secret Message");
        String encryptedMessageD = des.encrypt(secretMessage, secretKeyD);

        System.out.println("DES: ");
        System.out.println("Encrypted Message: " + encryptedMessageD);
        System.out.println("Decrypted Message: " + des.decrypt(encryptedMessageD, secretKeyD) + "\n") ;





    }
}
