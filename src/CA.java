import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.naming.NamingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

public class CA {

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

    public static List<String> getCrlDistributionPoints(X509Certificate certificate) throws IOException {

        if(certificate.getExtensionValue(X509Extensions.CRLDistributionPoints.getId()) != null) {
            ASN1InputStream oAsnInStream = new ASN1InputStream(certificate.getExtensionValue(X509Extensions.CRLDistributionPoints.getId()));
            DERObject derObjCrlDP = oAsnInStream.readObject();
            DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
            byte[] crldpExtOctets = dosCrlDP.getOctets();
            ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
            DERObject derObj2 = oAsnInStream2.readObject();
            CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

            List<String> crlUrls = new ArrayList<>();
            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                // Look for URIs in fullName
                if (dpn != null) {
                    if (dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralName[] genNames = GeneralNames.getInstance(
                                dpn.getName()).getNames();
                        // Look for an URI
                        for (int j = 0; j < genNames.length; j++) {
                            if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                                String url = DERIA5String.getInstance(
                                        genNames[j].getName()).getString();
                                crlUrls.add(url);
                            }
                        }
                    }
                }
            }
            return crlUrls;
        }
        else
            return null;
    }

    //Downloads CRL from given URL. Supports http, https, ftp and ldap based URLs.
    private static X509CRL downloadCRL(String crlURL) throws IOException, CertificateException, CRLException,
            NamingException {
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://") || crlURL.startsWith("ftp://")) {
            return downloadCRLFromWeb(crlURL);
        } else if (crlURL.startsWith("ldap://")) {
            System.out.println("Certificate revocation URL has ldap protocol which is not supported. Cannot verify CRL.");
//            return downloadCRLFromLDAP(crlURL); todo implement this
            throw new CertificateException("Can not download CRL from certificate distribution point: " + crlURL);
        } else {
            throw new CertificateException("Can not download CRL from certificate distribution point: " + crlURL);
        }
    }

    /**
     * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
     * http://crl.infonotary.com/crl/identity-ca.crl
     */
    private static X509CRL downloadCRLFromWeb(String crlURL) throws MalformedURLException,
            IOException, CertificateException,
            CRLException {
        URL url = new URL(crlURL);
        InputStream crlStream = url.openStream();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(crlStream);
        } finally {
            crlStream.close();
        }
    }

    public static void checkRevocation(X509Certificate certificate) throws CertificateException, IOException, CRLException, NamingException {

        System.out.println("[Verifying Revocation]");
        try {
            List<String> crlDistPoints = getCrlDistributionPoints(certificate);
            if (crlDistPoints == null){
                System.out.println("\tThe certificate is revoked");
                return;
            }
            else {
                for (String crlDP : crlDistPoints) {
                    X509CRL crl = downloadCRL(crlDP);
                    if (crl.isRevoked(certificate)) {
                        throw new CertificateException("\tThe certificate is revoked by CRL: " + crlDP);
                    }
                }
                System.out.println("\tThe certificate is not revoked by CRL");
            }
        } catch(Exception ex){
            if (ex instanceof CertificateException) {
                throw (CertificateException) ex;
            } else {
                throw new CertificateException("Can not verify CRL for certificate " + certificate.getSubjectX500Principal());
            }
        }

        System.out.println("[Verifying Date]");
        try {
            certificate.checkValidity();
            System.out.println("\tDate Verification : OK");
            return;
        } catch (CertificateExpiredException e) {
            System.out.println("\tDate Verification : Expired Certificate");
            return;
        } catch (CertificateNotYetValidException e) {
            System.out.println("\tDate Verification : Certificate not valid yet");
            return;
        }
    }

    public static String retrieveTSLCertificate() throws IOException, SAXException, ParserConfigurationException {

        String filename = "./ANTS_2D-DOc_TSL_230713_v3_signed.xml";
        File xmlFile = new File(filename);

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
                return tElement.getElementsByTagName("ds:X509Certificate").item(0).getTextContent();
            }
        }
        return null;
    }

    public static String retrieveTSLSignature() throws IOException, SAXException, ParserConfigurationException {

        String filename = "./ANTS_2D-DOc_TSL_230713_v3_signed.xml";
        File xmlFile = new File(filename);

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
                return tElement.getElementsByTagName("ds:SignatureValue").item(0).getTextContent();
            }
        }
        return null;
    }
}
