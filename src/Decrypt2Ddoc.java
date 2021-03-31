import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.imageio.ImageIO;
import javax.naming.NamingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Decrypt2Ddoc {

    public static void main(String[] args) throws Exception {
        String decodedQR = new String();
        CA CAcertificate = new CA();
        Info2Ddoc info = new Info2Ddoc();

        //Decode the image into a string
        System.out.println("======= Start decoding =======");
        File QRCodeImage = new File("./images/DC04-FR03.png");
        if (QRCodeImage != null) {
            decodedQR = readQRCode(QRCodeImage);
        } else {
            System.out.println("[ERROR] when opening the file");
        }

        System.out.println("======= Start retrieving informations =======");
        //Get the header of the entire decoded message
        String header = info.getHeader(decodedQR);
        System.out.println("[HEADER] " + header);

        //Get the ID of the Certificate Authority
        String IdCA = info.getCA(header);
        System.out.println("[CA] " + IdCA);

        //Get the Participant certificate ID
        String certID = info.getcertID(header);
        System.out.println("[Certificate ID] " + certID);

        //Get the url for all certificates
        String certURL = Info2Ddoc.getcertURL(IdCA);
        System.out.println("[Certificate URL] " + certURL);

        //Get the right Participant certificate from the URL
        byte[] certificate = getcert(certID, IdCA);

        //Get the CA certificate from the TSL
        X509Certificate certificateCA = convertToX509Cert(getcertCAinString(IdCA));


        System.out.println("\n======= Start checking =======");
        //Check the 2D doc signature with the participant public key
        System.out.println("\n2D-document : checking signature...");
        //TODO

        //Decode the participant certificate and check the signature with the CA public key
        System.out.println("\nParticipant : checking signature...");
        checkSignature(decodeX509(certificate), certificateCA);
        readCertificateInfo(decodeX509(certificate));

        //Decode and verify the date validity and the revocation of the Participant certificate
        System.out.println("\nParticipant : checking revocation...");
        CAcertificate.checkCA(decodeX509(certificate));

        //Decode and verify the date validity and the revocation of the CA certificate
        System.out.println("\nCertification Authority : checking revocation...");
        CAcertificate.checkCA(certificateCA);

        /* TEST POUR LE FR00 LA */
        //String certTest = "MIICVzCCAT8CCQCpMEvcR9M4RTANBgkqhkiG9w0BAQUFADBPMQswCQYDVQQGEwJGUjETMBEGA1UECgwKQUMgREUgVEVTVDEcMBoGA1UECwwTMDAwMiAwMDAwMDAwMDAwMDAwMDENMAsGA1UEAwwERlIwMDAeFw0xMjExMDExMzQ3NDZaFw0xNTExMDExMzQ3NDZaMFcxCzAJBgNVBAYTAkZSMRswGQYDVQQKDBJDRVJUSUZJQ0FUIERFIFRFU1QxHDAaBgNVBAsMEzAwMDIgMDAwMDAwMDAwMDAwMDAxDTALBgNVBAMMBDAwMDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASpjw18zWKAiJO+xNQ2550YNKHW4AHXDxxM3M2dni/iKfckBRTo3cDKmNDHRAycxJKEmg+9pz/DkvTaCuB/hMI8MA0GCSqGSIb3DQEBBQUAA4IBAQA6HN+w/bzIdg0ZQF+ELrocplehP7r5JuRJNBAgmoqoER7IonCvKSNUgUVbJ/MB4UKQ6CgzK7AOlCpiViAnBv+i6fg8Dh9evoUcHBiDvbl19+4iREaOoyVZ8RAlkp7VJKrC3s6dJEmI8/19obLbTvdHfY+TZfduqpVl63RSxwLG0Fjl0SAQz9a+KJSKZnEvT9I0iUUgCSnqFt77RSppziQTZ+rkWcfd+BSorWr8BHqOkLtj7EiVamIh+g3A8JtwV7nm+NUbBlhh2UPSI0eevsRjQRghtTiEn0wflVBX7xFP9zXpViHqIj+R9WiXzWGFYyKuAFK1pQ2QH8BxCbvdNdff";
        //checkSignature(convertStringToX509Cert(certTest), convertStringToX509Cert(certTest));

    }

    /*public static X509Certificate convertStringToX509Cert(String certificateString) throws CertificateException {
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
    }*/

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

    public static String getcertCAinString(String CA) throws IOException, SAXException, ParserConfigurationException {

        String filename = "./ANTS_2D-DOc_TSL_230713_v3_signed.xml";
        File xmlFile = new File(filename);

        char num = CA.toCharArray()[3];
        int pos = Character.getNumericValue(num);

        //Parsing the XML file
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        org.w3c.dom.Document doc = builder.parse(xmlFile);
        doc.getDocumentElement().normalize();

        //Searching for the right tag
        NodeList nodeList = doc.getElementsByTagName("tsl:TrustServiceStatusList");
        for (int i = 0; i < nodeList.getLength(); ++i) {
            Node node = nodeList.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element tElement = (Element) node;
                return tElement.getElementsByTagName("tsl:X509Certificate").item(pos - 1).getTextContent();
            }
        }
        return null;
    }

    public static byte[] getcert(String certID, String certCA) throws IOException {

        URL url;
        switch (certCA) {
            case "FR00":
                String cert = "MIICVzCCAT8CCQCpMEvcR9M4RTANBgkqhkiG9w0BAQUFADBPMQswCQYDVQQGEwJGUjETMBEGA1UECgwKQUMgREUgVEVTVDEcMBoGA1UECwwTMDAwMiAwMDAwMDAwMDAwMDAwMDENMAsGA1UEAwwERlIwMDAeFw0xMjExMDExMzQ3NDZaFw0xNTExMDExMzQ3NDZaMFcxCzAJBgNVBAYTAkZSMRswGQYDVQQKDBJDRVJUSUZJQ0FUIERFIFRFU1QxHDAaBgNVBAsMEzAwMDIgMDAwMDAwMDAwMDAwMDAxDTALBgNVBAMMBDAwMDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASpjw18zWKAiJO+xNQ2550YNKHW4AHXDxxM3M2dni/iKfckBRTo3cDKmNDHRAycxJKEmg+9pz/DkvTaCuB/hMI8MA0GCSqGSIb3DQEBBQUAA4IBAQA6HN+w/bzIdg0ZQF+ELrocplehP7r5JuRJNBAgmoqoER7IonCvKSNUgUVbJ/MB4UKQ6CgzK7AOlCpiViAnBv+i6fg8Dh9evoUcHBiDvbl19+4iREaOoyVZ8RAlkp7VJKrC3s6dJEmI8/19obLbTvdHfY+TZfduqpVl63RSxwLG0Fjl0SAQz9a+KJSKZnEvT9I0iUUgCSnqFt77RSppziQTZ+rkWcfd+BSorWr8BHqOkLtj7EiVamIh+g3A8JtwV7nm+NUbBlhh2UPSI0eevsRjQRghtTiEn0wflVBX7xFP9zXpViHqIj+R9WiXzWGFYyKuAFK1pQ2QH8BxCbvdNdff";
                byte[] array = cert.getBytes();
                return array;
            case "FR01":
                url = new URL("http://cert.pki-2ddoc.ariadnext.fr/pki-2ddoc.der");
                break;
            case "FR02":
                url = new URL("http://pki-2ddoc.sunnystamp.com/certs/pki_fr02_rfc4387_certstore_file.der");
                break;
            case "FR03":
                url = new URL("http://certificates.certigna.fr/search.php?name=" + certID);
                break;
            case "FR04":
                url = new URL("http://pki-g2.ariadnext.fr/pki-2ddoc.der");
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

    /*public void verify2Dsignature(X509Certificate certificate) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec participantPubKeySpec = new X509EncodedKeySpec(certificate.getSignature());
        Signature sig = Signature.getInstance("RSA");
        sig.initVerify(certificate.getPublicKey());
        sig.update();
        sig.verify(signature);
    }*/

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
}
