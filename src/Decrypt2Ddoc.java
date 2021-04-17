import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;
import org.apache.commons.codec.binary.Base32;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import javax.imageio.ImageIO;
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
        Info2Ddoc info = new Info2Ddoc();

        //Decode the image into a string
        System.out.println("\u001B[33m======= Start decoding =======\u001B[0m\n");
        File QRCodeImage = new File("./images/DC02-FR04.png");
        if (QRCodeImage != null) {
            decodedQR = info.readQRCode(QRCodeImage);
        } else {
            System.out.println("[ERROR] when opening the file");
        }

        System.out.println("\u001B[33m======= Start retrieving informations =======\u001B[0m\n");
        //Get the header of the entire decoded message
        String header = info.getHeader(decodedQR);
        System.out.println("[HEADER] " + header);

        //Get the data of the entire decoded message
        String data = info.getMessage(decodedQR);
        System.out.println("[DATA] " + data);

        //Display the contain of the message
        DisplayInfo disInfo = new DisplayInfo();
        disInfo.printMessageInfo(data);
        String DocType = info.getDocType(header);
        System.out.println("\t- Type de document : " + DocType);

        //Get the signature of the entire decoded message
        String signature2Ddoc = info.getSignature(decodedQR);
        System.out.println("[SIGNATURE] " + signature2Ddoc);

        //Get the ID of the Certificate Authority
        String IdCA = info.getCA(header);
        System.out.println("[CertificateManage] " + IdCA);

        //Get the Participant certificate ID
        String certID = info.getcertID(header);
        System.out.println("[Certificate ID] " + certID);

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
            certificate = CertificateManage.getParticipantCert(certID, IdCA);
            certPart = CertificateManage.decodeX509(certificate);
        }
        else
            cert = "MIICVzCCAT8CCQCpMEvcR9M4RTANBgkqhkiG9w0BAQUFADBPMQswCQYDVQQGEwJGUjETMBEGA1UECgwKQUMgREUgVEVTVDEcMBoGA1UECwwTMDAwMiAwMDAwMDAwMDAwMDAwMDENMAsGA1UEAwwERlIwMDAeFw0xMjExMDExMzQ3NDZaFw0xNTExMDExMzQ3NDZaMFcxCzAJBgNVBAYTAkZSMRswGQYDVQQKDBJDRVJUSUZJQ0FUIERFIFRFU1QxHDAaBgNVBAsMEzAwMDIgMDAwMDAwMDAwMDAwMDAxDTALBgNVBAMMBDAwMDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASpjw18zWKAiJO+xNQ2550YNKHW4AHXDxxM3M2dni/iKfckBRTo3cDKmNDHRAycxJKEmg+9pz/DkvTaCuB/hMI8MA0GCSqGSIb3DQEBBQUAA4IBAQA6HN+w/bzIdg0ZQF+ELrocplehP7r5JuRJNBAgmoqoER7IonCvKSNUgUVbJ/MB4UKQ6CgzK7AOlCpiViAnBv+i6fg8Dh9evoUcHBiDvbl19+4iREaOoyVZ8RAlkp7VJKrC3s6dJEmI8/19obLbTvdHfY+TZfduqpVl63RSxwLG0Fjl0SAQz9a+KJSKZnEvT9I0iUUgCSnqFt77RSppziQTZ+rkWcfd+BSorWr8BHqOkLtj7EiVamIh+g3A8JtwV7nm+NUbBlhh2UPSI0eevsRjQRghtTiEn0wflVBX7xFP9zXpViHqIj+R9WiXzWGFYyKuAFK1pQ2QH8BxCbvdNdff";

        //Get the CertificateManage certificate from the TSL
        X509Certificate certificateCA = null;
        if(!IdCA.equals("FR00")) {
            certificateCA = convertToX509Cert(CertificateManage.getcertCAinString(IdCA));
        }

        System.out.println("\n\u001B[33m======= Start checking =======\u001B[0m");
        //Check the 2D doc signature with the participant public key
        System.out.println("\n2D-document : checking signature...");
        if(!IdCA.equals("FR00")) {
            verify2Dsignature(certPart, signature2Ddoc, header, data);
        } else {
            verify2Dsignature(CertificateManage.convertStringToX509Cert(cert), signature2Ddoc, header, data);
        }
        //Decode the participant certificate and check the signature with the CertificateManage public key
        if(!IdCA.equals("FR00")){
            System.out.println("\nParticipant : checking signature...");
            CertificateManage.checkSignature(certPart, certificateCA);
            CertificateManage.readCertificateInfo(certPart);
        }

        //Decode and verify the date validity and the revocation of the Participant certificate
        System.out.println("\nParticipant : checking revocation...");
        if(IdCA.equals("FR00")) {
            CertificateManage.checkRevocation(CertificateManage.convertStringToX509Cert(cert));
            CertificateManage.readCertificateInfo(CertificateManage.convertStringToX509Cert(cert));
        } else {
            CertificateManage.checkRevocation(certPart);
        }

        //Decode and verify the date validity and the revocation of the CertificateManage certificate
        if(!IdCA.equals("FR00")) {
            System.out.println("\nCertification Authority : checking revocation...");
            CertificateManage.checkRevocation(certificateCA);
        }

        //Verify the signature of the CertificateManage certificate
        if(!IdCA.equals("FR00")) {
            System.out.println("\nCertification Authority : checking signature...");
            CertificateManage.checkCASignature(certificateCA, IdCA);
            CertificateManage.readCertificateInfo(certificateCA);
        }

        //Decode and verify the TSL
        //TODO
        String TSLcertificate = CertificateManage.retrieveTSLCertificate();
        TSLcertificate = TSLcertificate.replaceAll("\\s", "");
        TSLcertificate = TSLcertificate.replaceAll(String.valueOf(Character.LINE_SEPARATOR), "");
        System.out.println("\nTSL certificate : "+TSLcertificate);
        String TSLsignature = CertificateManage.retrieveTSLSignature();
        System.out.println("\nTSL signature : "+TSLsignature);

        X509Certificate TSLX509Cert = CertificateManage.convertStringToX509Cert(TSLcertificate);
        checkTSLSignature(TSLX509Cert, TSLsignature, TSLcertificate);
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
            System.out.println("\tSignature 2D Doc : OK");
        else
            System.out.println("\tSignature 2D Doc : KO");
    }

    public static void checkTSLSignature(X509Certificate TSLcertificate, String signature, String test) throws Exception {
        VerifySignature verif = new VerifySignature();
        boolean isValid = verif.isXmlDigitalSignatureValid( "./ANTS_2D-DOc_TSL_230713_v3_signed.xml",TSLcertificate.getPublicKey());
        if (isValid == true)
            System.out.println("\tSignature TSL : OK");
        else
            System.out.println("\tSignature TSL : KO");

    }
}
