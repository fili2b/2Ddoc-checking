import com.chilkatsoft.CkAsn;
import com.chilkatsoft.CkByteData;
import com.chilkatsoft.CkXml;
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
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.ArrayList;


public class Decrypt2Ddoc {

    private static class QRInfo {
        String version = "";
        String CA = "";
        String CID = "";
        String URL = "";
        String message = "";
        String signature = "";
    }

    static {
        try {
            System.loadLibrary("chilkat");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            System.exit(1);
        }
    }

    public static void main(String[] args) throws Exception {
        String decodedQR = new String();

        System.out.println("======= Start decoding =======");
        //File QRCodeImage = new File("./images/94-1.jpg");
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
        System.out.println("[Certificate] " + certificate);

        decodeASN1(certID, certificate);


        //Print the certificate
        //X509Certificate cert = convertToX509Cert(certificate);

        //extract signature / clé
        //check signature
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
        //BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        BufferedInputStream bis = new BufferedInputStream(url.openStream());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        //La ligne courante
        //String inputLine;
        byte data[] = new byte[1024];
        
        //Le contenu de la reponse GET
        //StringBuffer content = new StringBuffer();
        int byteContent;

        /* Pour chaque ligne dans la reponse GET */
        /*while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }*/
        while ((byteContent = bis.read(data,0,1024)) != -1) {
            baos.write(data, 0, byteContent);
        }

        byte[] allBytes = baos.toByteArray();

        System.out.println("Taille: "+allBytes.length);
        //Ferme BufferedReader
        //in.close();
        //return content.toString();
        return allBytes;
    }


    /*public static X509Certificate convertToX509Cert(String certificateString) throws CertificateException {
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
            if (certificateString != null && !certificateString.trim().isEmpty()) {
                certificateString = certificateString.replace("-----BEGIN CERTIFICATE-----\n", "")
                        .replace("-----END CERTIFICATE-----", ""); // NEED FOR PEM FORMAT CERT STRING
                byte[] certificateData = Base64.getMimeDecoder().decode(certificateString);
                cf = CertificateFactory.getInstance("X509");
                certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
            }
        } catch (CertificateException e) {
            throw new CertificateException(e);
        }
        System.out.println("Read in the following certificate:");
        System.out.println("\tCertificate for: " + certificate.getSubjectDN());
        System.out.println("\tCertificate issued by: " + certificate.getIssuerDN());
        System.out.println("\tThe certificate is valid from " + certificate.getNotBefore() + " to " + certificate.getNotAfter());
        System.out.println("\tCertificate SN# " + certificate.getSerialNumber());
        System.out.println("\tGenerated with " + certificate.getSigAlgName());
        return certificate;
    }*/

    public static void decodeASN1(String certID, byte[] cert) {
        CkAsn asn = new CkAsn();
        boolean success;

        CkByteData myData = new CkByteData();
        myData.appendByteArray(cert);


        //  Begin with loading ASN.1 from a binary DER/BER format file.
        //success = asn.LoadBinaryFile("/home/matthieu/Documents/CIR4/Crypto/Projet/"+certID+".der");
        success = asn.LoadBinary(myData);
        if (success != true) {
            System.out.println(asn.lastErrorText());
            return;
        }
        //  Convert ASN.1 to XML:
        String strXml = asn.asnToXml();
        if (asn.get_LastMethodSuccess() != true) {
            System.out.println(asn.lastErrorText());
            return;
        }
        //  The XML returned by AsnToXml will be compact and not pretty-formatted.
        //  Use Chilkat XML to format the XML better:
        CkXml xml = new CkXml();
        success = xml.LoadXml(strXml);
        //  Assuming success for this example..
        //  This is formatted better for human viewing:
        System.out.println(xml.getXml());
        //  Now get the ASN.1 in base64 format.  Any encoding supported
        //  by Chilkat can be passed, such as "hex", "uu", "quoted-printable", "base32", "modbase64", etc.
        String strBase64 = asn.getEncodedDer("base64");
        //  Load the ASN.1 from XML:
        CkAsn asn2 = new CkAsn();
        success = asn2.LoadAsnXml(xml.getXml());
        if (success != true) {
            System.out.println(asn2.lastErrorText());
            return;
        }
        //  Load the ASN.1 from an encoded string, such as base64:
        CkAsn asn3 = new CkAsn();
        success = asn3.LoadEncoded(strBase64,"base64");
        if (success != true) {
            System.out.println(asn3.lastErrorText());
            return;
        }
    }
}
