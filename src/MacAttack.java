import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class MacAttack {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //Création de la clé
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(new SecureRandom());
        SecretKey key = kg.generateKey();


        System.out.println("---------------Obtention de MAC1---------------");
        byte[] M1 = "Hello guys! I'm waiting for you".getBytes();
        //Création du mac1
        Mac mac1 = Mac.getInstance("AES/CBC/PKCS5Padding");
        mac1.init(key);
        mac1.doFinal(M1);

        System.out.println("---------------Obtention de MAC2---------------");
        byte[] M2 = "Sorry! We're on the road".getBytes();
        //Création du mac2
        Mac mac2 = Mac.getInstance("AES/CBC/PKCS5Padding");
        mac2.init(key);
        mac2.doFinal(M2);

        System.out.println("---------------Obtention de MAC3---------------");
        //Opération XOR
        byte[] M2prim = M2;
        byte[] p1 = new byte[16];
        for(int i=0; i<16; i++)
            p1[i] = M2[i];
        //M2prim[0] = mac1 ^ p1;
        //Concaténation de M1 et M2 dans M3
        byte[] M3 = new byte [M1.length+M2prim.length];
        System.arraycopy(M2,0, M1, 0, M2prim.length);
        System.arraycopy(M1,0, M3, 0, M1.length);
        //Création du mac3
        Mac mac3 = Mac.getInstance("AES/CBC/PKCS5Padding");
        mac3.init(key);
        mac3.doFinal(M3);

        System.out.println("-----------------Verification-----------------");
        System.out.println("Mac2 = "+mac2);
        System.out.println("Mac3 = "+mac3);
    }
}
