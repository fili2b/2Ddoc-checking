package TPCrypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CipherExo {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //Chiffrement
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        kg.init(new SecureRandom());
        SecretKey key = kg.generateKey();

        System.out.println("---------------Chiffrement---------------");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] input1 = "hi guys!".getBytes();
        byte[] cipherInput1 = cipher.doFinal(input1);
        System.out.println("Input : 'hello guys'");
        System.out.println("Input in bytes :"+ input1);
        System.out.println("Input ciphered : ");
        for(int i=0; i<input1.length; i++){
            System.out.print(input1[i]+" ");
        }

        //Chiffrement avec modification du plain text
        /*byte[] input2 = "he guys!".getBytes();
        byte[] cipherInput2 = cipher.doFinal(input2);
        System.out.println("Input : 'hallo guys'");
        System.out.println("Initial text  :"+ input2);
        System.out.println("Cipher text : "+cipherInput2);*/

        //Dechiffrement
        System.out.println("\n--------------Dechiffrement--------------");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decipherInput = cipher.doFinal(cipherInput1);
        System.out.println("Input decrypted in bytes :");
        for(int i=0; i<decipherInput.length; i++){
            System.out.print(decipherInput[i]+" ");
        }
    }
}
