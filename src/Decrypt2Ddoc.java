import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;
import org.apache.commons.codec.binary.Base32;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.w3c.dom.NodeList;

import javax.imageio.ImageIO;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import java.awt.image.BufferedImage;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

//import javax.xml.*;

public class Decrypt2Ddoc {

    public static void main(String[] args) throws Exception {
        String decodedQR = new String();
        CA CAcertificate = new CA();
        Info2Ddoc info = new Info2Ddoc();

        //Decode the image into a string
        System.out.println("======= Start decoding =======");
        File QRCodeImage = new File("./images/DC04-FR00.png");
        if (QRCodeImage != null) {
            decodedQR = readQRCode(QRCodeImage);
        } else {
            System.out.println("[ERROR] when opening the file");
        }

        System.out.println("======= Start retrieving informations =======");
        //Get the header of the entire decoded message
        String header = info.getHeader(decodedQR);
        System.out.println("[HEADER] " + header);

        //Get the data of the entire decoded message
        String data = info.getMessage(decodedQR);
        System.out.println("[DATA] " + data);

        //Display the contain of the message
        DisplayInfo disInfo = new DisplayInfo();
        disInfo.printMessageInfo(data);

        //Get the signature of the entire decoded message
        String signature2Ddoc = info.getSignature(decodedQR);
        System.out.println("[SIGNATURE] " + signature2Ddoc);

        //Get the ID of the Certificate Authority
        String IdCA = info.getCA(header);
        System.out.println("[CA] " + IdCA);

        //Get the Participant certificate ID
        String certID = info.getcertID(header);
        System.out.println("[Certificate ID] " + certID);

        //Get the Document's type
       // String DocType = info.getDocType(header);
        //System.out.println("[Doc Type] " + DocType);

        //Get the url for all certificates
        if(!IdCA.equals("FR00")){
            String certURL = Info2Ddoc.getcertURL(IdCA);
            System.out.println("[Certificate URL] " + certURL);
        }

        //Get the right Participant certificate from the URL
        String cert = null;
        byte[] certificate;
        X509Certificate certPart = null;
        if(!IdCA.equals("FR00")){
            certificate = getParticipantCert(certID, IdCA);
            certPart = decodeX509(certificate);
        }
        else
            cert = "MIICVzCCAT8CCQCpMEvcR9M4RTANBgkqhkiG9w0BAQUFADBPMQswCQYDVQQGEwJGUjETMBEGA1UECgwKQUMgREUgVEVTVDEcMBoGA1UECwwTMDAwMiAwMDAwMDAwMDAwMDAwMDENMAsGA1UEAwwERlIwMDAeFw0xMjExMDExMzQ3NDZaFw0xNTExMDExMzQ3NDZaMFcxCzAJBgNVBAYTAkZSMRswGQYDVQQKDBJDRVJUSUZJQ0FUIERFIFRFU1QxHDAaBgNVBAsMEzAwMDIgMDAwMDAwMDAwMDAwMDAxDTALBgNVBAMMBDAwMDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASpjw18zWKAiJO+xNQ2550YNKHW4AHXDxxM3M2dni/iKfckBRTo3cDKmNDHRAycxJKEmg+9pz/DkvTaCuB/hMI8MA0GCSqGSIb3DQEBBQUAA4IBAQA6HN+w/bzIdg0ZQF+ELrocplehP7r5JuRJNBAgmoqoER7IonCvKSNUgUVbJ/MB4UKQ6CgzK7AOlCpiViAnBv+i6fg8Dh9evoUcHBiDvbl19+4iREaOoyVZ8RAlkp7VJKrC3s6dJEmI8/19obLbTvdHfY+TZfduqpVl63RSxwLG0Fjl0SAQz9a+KJSKZnEvT9I0iUUgCSnqFt77RSppziQTZ+rkWcfd+BSorWr8BHqOkLtj7EiVamIh+g3A8JtwV7nm+NUbBlhh2UPSI0eevsRjQRghtTiEn0wflVBX7xFP9zXpViHqIj+R9WiXzWGFYyKuAFK1pQ2QH8BxCbvdNdff";

        //Get the CA certificate from the TSL
        X509Certificate certificateCA = null;
        if(!IdCA.equals("FR00")) {
            certificateCA = convertToX509Cert(CA.getcertCAinString(IdCA));
        }

        System.out.println("\n======= Start checking =======");
        //Check the 2D doc signature with the participant public key
        System.out.println("\n2D-document : checking signature...");
        if(!IdCA.equals("FR00")) {
            verify2Dsignature(certPart, signature2Ddoc, header, data);
        } else {
            readCertificateInfo(convertStringToX509Cert(cert));
            verify2Dsignature(convertStringToX509Cert(cert), signature2Ddoc, header, data);
        }
        //Decode the participant certificate and check the signature with the CA public key
        if(!IdCA.equals("FR00")){
            System.out.println("\nParticipant : checking signature...");
            checkSignature(certPart, certificateCA);
            readCertificateInfo(certPart);
        }

        //Decode and verify the date validity and the revocation of the Participant certificate
        System.out.println("\nParticipant : checking revocation...");
        if(IdCA.equals("FR00")) {
            CAcertificate.checkRevocation(convertStringToX509Cert(cert));
        } else{
            CAcertificate.checkRevocation(certPart);
        }

        //Decode and verify the date validity and the revocation of the CA certificate
        System.out.println("\nCertification Authority : checking revocation...");
        if(!IdCA.equals("FR00")) {
            CAcertificate.checkRevocation(certificateCA);
        }
        
        //Decode and verify the TSL
        //TODO
        String TSLcertificate = CA.retrieveTSLCertificate();
        TSLcertificate = TSLcertificate.replaceAll("\\s", "");
        TSLcertificate = TSLcertificate.replaceAll(String.valueOf(Character.LINE_SEPARATOR), "");
        System.out.println("\nTSL certificate : "+TSLcertificate);
        String TSLsignature = CA.retrieveTSLSignature();
        System.out.println("\nTSL signature : "+TSLsignature);

        X509Certificate TSLX509Cert = convertStringToX509Cert(TSLcertificate);
        //readCertificateInfo(TSLX509Cert);

        checkTSLSignature(TSLX509Cert, TSLsignature, TSLcertificate);

    }

    public static String readQRCode(File fileName) {
        BufferedImage image;
        BinaryBitmap bitmap = null;
        Result result;

        try {
            image = ImageIO.read(fileName);
            int[] pixels = image.getRGB(0, 0, image.getWidth(), image.getHeight(), null, 0, image.getWidth());
            RGBLuminanceSource source = new RGBLuminanceSource(image.getWidth(), image.getHeight(), pixels);
            bitmap = new BinaryBitmap(new HybridBinarizer(source));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (bitmap == null)
            return null;

        try {
            MultiFormatReader reader = new MultiFormatReader();// use this otherwise

            result = reader.decodeWithState(bitmap);
            System.out.println("[QR code result] " + result.getText());
            return result.getText();
        } catch (NotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] getParticipantCert(String certID, String certCA) throws IOException {

        URL url;
        switch (certCA) {
            case "FR01":
                url = new URL("http://cert.pki-2ddoc.ariadnext.fr/pki-2ddoc.der?name="+certID);
                break;
            case "FR02":
                url = new URL("http://pki-2ddoc.sunnystamp.com/certs/pki_fr02_rfc4387_certstore_file.der?name="+certID);
                break;
            case "FR03":
                url = new URL("http://certificates.certigna.fr/search.php?name=" + certID);
                break;
            case "FR04":
                url = new URL("http://pki-g2.ariadnext.fr/pki-2ddoc.der?name="+certID);
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + certCA);
        }

        /* Ouvre une connection avec l'object URL */
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        //GET method
        connection.setRequestMethod("GET");
        /* Utilise BufferedReader pour lire ligne par ligne */
        BufferedInputStream bis = new BufferedInputStream(url.openStream());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        //La ligne courante
        byte data[] = new byte[1024];

        //Le contenu de la reponse GET
        int byteContent;

        while ((byteContent = bis.read(data, 0, 1024)) != -1) {
            baos.write(data, 0, byteContent);
        }

        byte[] allBytes = baos.toByteArray();

        //System.out.println("Taille: " + allBytes.length);
        return allBytes;
    }

    public static X509Certificate convertToX509Cert(String certificateString) throws CertificateException {
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
            if (certificateString != null && !certificateString.trim().isEmpty()) {
                certificateString = certificateString.replace("-----BEGIN CERTIFICATE-----\n", "")
                        .replace("-----END CERTIFICATE-----", ""); // NEED FOR PEM FORMAT CERT STRING
                byte[] certificateData = Base64.getDecoder().decode(certificateString);
                cf = CertificateFactory.getInstance("X509");
                certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
            }
        } catch (CertificateException e) {
            throw new CertificateException(e);
        }
        return certificate;
    }

    public static X509Certificate convertStringToX509Cert(String certificateString) throws CertificateException {
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
            if (certificateString != null && !certificateString.trim().isEmpty()) {
                certificateString = certificateString.replace("-----BEGIN CERTIFICATE-----\n", "")
                        .replace("-----END CERTIFICATE-----", ""); // NEED FOR PEM FORMAT CERT STRING
                byte[] certificateData = Base64.getDecoder().decode(certificateString);
                cf = CertificateFactory.getInstance("X509");
                certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
            }
        } catch (CertificateException e) {
            throw new CertificateException(e);
        }
        return certificate;
    }

    public static String printByteToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    public static X509Certificate decodeX509(byte[] cert) throws CertificateException {
        InputStream targetStream = new ByteArrayInputStream(cert);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(targetStream);
        return certificate;
    }

    public static void readCertificateInfo(X509Certificate certificate) throws CertificateException {
        System.out.println("[Read in the participant certificate]");
        System.out.println("\t- Certificate for: " + certificate.getSubjectDN());
        System.out.println("\t- Certificate issued by: " + certificate.getIssuerDN());
        System.out.println("\t- The certificate is valid from " + certificate.getNotBefore() + " to " + certificate.getNotAfter());
        System.out.println("\t- Certificate SN# " + certificate.getSerialNumber());
        System.out.println("\t- Generated with " + certificate.getSigAlgName());
        System.out.println("\t- Signature: " + printByteToHex(certificate.getSignature()));
    }

    private static byte[] toDerSignature(byte[] jwsSig) {

        byte[] rBytes = Arrays.copyOfRange(jwsSig, 0, 32);
        byte[] sBytes = Arrays.copyOfRange(jwsSig, 32, 64);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        DERSequence sequence = new DERSequence(new ASN1Encodable[] {
                new ASN1Integer(r),
                new ASN1Integer(s)
        });

        return sequence.getDEREncoded();
    }

    public static void verify2Dsignature(X509Certificate certificate, String signature2Ddoc, String header, String message) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException {
        Base32 base32 = new Base32();
        byte[] signature = base32.decode(signature2Ddoc);
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(certificate.getPublicKey());
        String data = header+message;
        String newData = (new StringBuilder(data)).deleteCharAt(data.length()-1).toString();
        sig.update(newData.getBytes(StandardCharsets.UTF_8));
        if (sig.verify(toDerSignature(signature)) == true)
            System.out.println("Signature 2D Doc : OK");
        else
            System.out.println("Signature 2D Doc : KO");
    }

    public static boolean checkSignature(X509Certificate certificate, X509Certificate certificateCA) {

        if (!certificateCA.getSubjectDN().equals(certificate.getIssuerDN())) {
            System.out.println("\tSignature Verification : KO same issuer and subject");
            return false;
        }
        System.out.println("[Verifying Signature]");
        try {
            certificate.verify(certificateCA.getPublicKey());
            System.out.println("\tSignature Verification : OK");
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e) {
            System.out.println("\tSignature Verification : KO");
            return false;
        } catch (Exception e) {
            System.out.println("\tSignature Verification : error");
            return false;
        }
    }

    public static void checkTSLSignature(X509Certificate TSLcertificate, String signature, String test) throws Exception {

        /*System.out.println("[Verifying TSL Signature]");
        try {
            TSLcertificate.verify(TSLcertificate.getPublicKey());
            System.out.println("\tSignature Verification : OK");
            return;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e) {
            System.out.println("\tSignature Verification : KO");
            return;
        } catch (Exception e) {
            System.out.println("\tSignature Verification : error -> "+e);
            return;
        }*/
        byte[] sign = Base64.getDecoder().decode(signature);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(TSLcertificate.getPublicKey());
        String BIGdataTSL = "";
        sig.update(BIGdataTSL.getBytes(StandardCharsets.UTF_8));
        VerifySignature verif = new VerifySignature();
        boolean isValid = verif.isXmlDigitalSignatureValid( "./ANTS_2D-DOc_TSL_230713_v3_signed.xml",TSLcertificate.getPublicKey());
        if (isValid == true)
            System.out.println("Signature TSL : OK");
        else
            System.out.println("Signature TSL : KO");

    }
}
