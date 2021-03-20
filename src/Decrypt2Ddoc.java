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
        System.out.println("[Certificate Retrieved]");

        //Get the CA certificate from the TSL
        //TODO : parse the TSL to get the x509 certificate string (do not hard code it as below)
        String certCA = "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";
        X509Certificate certificateCA = convertToX509Cert(certCA);
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
            //result = reader.decode(bitmap);
            System.out.println("Resultat : " + result.getText());
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
            //System.out.println("\nNode Name :" + node.getNodeName());
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element tElement = (Element) node;
                //System.out.println("URI: " + tElement.getElementsByTagName("tsl:TSPInformationURI").item(0).getTextContent());
                return tElement.getElementsByTagName("tsl:TSPInformationURI").item(pos-1).getTextContent();
            }
        }
        return null;
    }

    public static byte[] getcert(String certID, String certURL) throws IOException {
        //URL url = new URL(certURL);
        //URL url = new URL("http://certificates.certigna.fr/search.php?name=0001");
        URL url = new URL("http://certificates.certigna.fr/search.php?name="+certID);

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

        while ((byteContent = bis.read(data,0,1024)) != -1) {
            baos.write(data, 0, byteContent);
        }

        byte[] allBytes = baos.toByteArray();

        System.out.println("Taille: "+allBytes.length);
        return allBytes;
    }

    public static byte[] getcertCA(String certID) throws IOException {
        //URL url = new URL(certURL);
        //URL url = new URL("http://certificates.certigna.fr/search.php?name=0001");
        URL url = new URL("http://certificates.certigna.fr/search.php?name="+certID);

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

        while ((byteContent = bis.read(data,0,1024)) != -1) {
            baos.write(data, 0, byteContent);
        }

        byte[] allBytes = baos.toByteArray();

        System.out.println("Taille: "+allBytes.length);
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

        System.out.println("Read in the following certificate:");
        System.out.println("\tCertificate for: " + certificate.getSubjectDN());
        System.out.println("\tCertificate issued by: " + certificate.getIssuerDN());
        System.out.println("\tThe certificate is valid from " + certificate.getNotBefore() + " to " + certificate.getNotAfter());
        System.out.println("\tCertificate SN# " + certificate.getSerialNumber());
        System.out.println("\tGenerated with " + certificate.getSigAlgName());
        System.out.println("\tSignature: "+printByteToHex(certificate.getSignature()));
        return certificate;
    }

    public static boolean checkSignature(X509Certificate certificate, X509Certificate certificateCA){

        if (!certificateCA.getSubjectDN().equals(certificate.getIssuerDN())) {
            return false;
        }
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
