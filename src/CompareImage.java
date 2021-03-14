import java.awt.Image;
import java.awt.Toolkit;
import java.awt.image.PixelGrabber;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class CompareImage {

    private static final int PIXELS_OFFSET = 0x0000000A;

    public static void main(String[] args) {

        Path encryptedTextPath1 = Paths.get("./images/encryptedtext1.bmp");
        Path encryptedTextPath2 = Paths.get("./images/encryptedtext2.bmp");
        Path xorpath = Paths.get("./xor-result.bmp");
        byte[] image1 = new byte[0];
        try {
            image1 = Files.readAllBytes(encryptedTextPath1);
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] image2 = new byte[0];
        try {
            image2 = Files.readAllBytes(encryptedTextPath2);
        } catch (IOException e) {
            e.printStackTrace();
        }

        int pixelsOffset1 = Array.getInt(image1, PIXELS_OFFSET);
        byte [] xoredImages = image1.clone();

        for(int i=pixelsOffset1; i<image1.length; i++){
            xoredImages[i] = (byte) (image1[i] ^ image2[i]);
        }

        try {
            Files.write(xorpath,xoredImages, StandardOpenOption.CREATE);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}