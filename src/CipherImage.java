import javax.crypto.*;
import java.io.IOException;
import java.lang.reflect.Array;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CipherImage {

    private static final int PIXELS_OFFSET = 0x0000000A;

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        //Récupération des images
        Path ISENPath = Paths.get("./images/ISEN.bmp");
        Path ECBpath = Paths.get("./ECBimage.bmp");
        Path CBCpath = Paths.get("./CBCimage.bmp");

        //Initialisation de l'image
        byte[] ISENimage = Files.readAllBytes(ISENPath);
        int pixelsOffset1 = Array.getInt(ISENimage, PIXELS_OFFSET);
        byte[] ISENimageNoHead = new byte[ISENimage.length];

        //On vire le header
        int j=0;
        for (int i=pixelsOffset1; i<ISENimage.length; i++)
        {
            ISENimageNoHead[j] = ISENimage[i];
            j++;
        }

        //Création de la clé
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(new SecureRandom());
        SecretKey key = kg.generateKey();

        //Chiffrement en ECB
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ecbimage = cipher.doFinal(ISENimageNoHead);

        //On replace le header
        int l = 0;
        for (int i=pixelsOffset1; i<ISENimage.length; i++)
        {
            ISENimage[i] = ecbimage[l];
            l++;
        }
        Files.write(ECBpath, ISENimage, StandardOpenOption.CREATE);

        //Chiffrement en CBC
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cbcimage = cipher.doFinal(ISENimageNoHead);
        
        //On replace le header
        int k = 0;
        for (int i=pixelsOffset1; i<ISENimage.length; i++)
        {
            ISENimage[i] = cbcimage[k];
            k++;
        }
        Files.write(CBCpath, ISENimage, StandardOpenOption.CREATE);
    }
}
