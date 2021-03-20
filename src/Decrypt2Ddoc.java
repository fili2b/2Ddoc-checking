import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.imageio.ImageIO;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Decrypt2Ddoc {

    public static void main(String[] args) throws Exception {
        String decodedQR = new String();

        System.out.println("======= Start decoding =======");
        File QRCodeImage = new File("./images/2Ddoc.png");
        if (QRCodeImage != null) {
            System.out.println("=======  Image loaded  =======");
            decodedQR = readQRCode(QRCodeImage);
        } else {
            System.out.println("[ERROR] when opening the file");
        }

        //Get the header of the entire decoded message
        String header = getHeader(decodedQR);
        System.out.println("[HEADER] " + header);

        //Get the Certificate Authority
        String CA = getCA(header);
        System.out.println("[CA] " + CA);

        //Get the ID of the certificate
        String certID = getcertID(header);
        System.out.println("[Certificate ID] " + certID);

        //Get the url for all certificates
        String certURL = getcertURL(CA);
        System.out.println("[Certificate URL] " + certURL);

        //Get the right certificate from the URL
        byte[] certificate = getcert(certID, certURL);
        System.out.println("\n[Certificate Retrieved]");

        //Get the CA certificate from the TSL
        X509Certificate certificateCA = convertToX509Cert(getcertCAinString(CA));
        System.out.println("[CA Certificate Retrieved]");

        //Decode the participant certificate and check the signature with the CA public key
        checkSignature(decodeX509(certID, certificate), certificateCA);

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

    public static String getHeader(String data) {
        char[] dataArray = data.toCharArray();
        if (dataArray[3] == '1' || dataArray[3] == '2') {
            char[] header = new char[22];
            data.getChars(0, 22, header, 0);
            return String.valueOf(header);
        } else if (dataArray[3] == '3') {
            //TODO
        } else if (dataArray[3] == '4') {
            char[] header = new char[26];
            data.getChars(0, 26, header, 0);
            return String.valueOf(header);
        }
        return null;
    }

    public static String getCA(String header) {
        char[] CA = new char[4];
        header.getChars(4, 8, CA, 0);
        return String.valueOf(CA);
    }

    public static String getcertID(String header) {
        char[] certID = new char[4];
        header.getChars(8, 12, certID, 0);
        return String.valueOf(certID);
    }

    public static String getcertURL(String CA) throws IOException, SAXException, ParserConfigurationException {
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
                return tElement.getElementsByTagName("tsl:TSPInformationURI").item(pos - 1).getTextContent();
            }
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
                //System.out.println("cert CA string: " + tElement.getElementsByTagName("tsl:X509Certificate").item(0).getTextContent());
                return tElement.getElementsByTagName("tsl:X509Certificate").item(pos - 1).getTextContent();
            }
        }
        return null;
    }

    public static byte[] getcert(String certID, String certURL) throws IOException {
        //URL url = new URL(certURL);
        //URL url = new URL("http://certificates.certigna.fr/search.php?name=0001");
        URL url = new URL("http://certificates.certigna.fr/search.php?name=" + certID);

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

    public static X509Certificate decodeX509(String certID, byte[] cert) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        InputStream targetStream = new ByteArrayInputStream(cert);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(targetStream);

        System.out.println("[Read in the participant certificate]");
        System.out.println("\tCertificate for: " + certificate.getSubjectDN());
        System.out.println("\tCertificate issued by: " + certificate.getIssuerDN());
        System.out.println("\tThe certificate is valid from " + certificate.getNotBefore() + " to " + certificate.getNotAfter());
        System.out.println("\tCertificate SN# " + certificate.getSerialNumber());
        System.out.println("\tGenerated with " + certificate.getSigAlgName());
        System.out.println("\tSignature: " + printByteToHex(certificate.getSignature()));
        return certificate;
    }

    public static boolean checkSignature(X509Certificate certificate, X509Certificate certificateCA) {

        if (!certificateCA.getSubjectDN().equals(certificate.getIssuerDN())) {
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
