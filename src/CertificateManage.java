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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class CertificateManage {


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////// CONVERSION OPERATIONS /////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////


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


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////// RETRIEVE CERTIFICATES /////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////


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


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////// DISTRIBUTION POINT /////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////


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



    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /////////////////////////////////////////// VERIFY SIGNATURES ///////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////



    public static boolean checkSignature(X509Certificate certificate, X509Certificate certificateCA) {

        System.out.println("[Verifying Signature]");
        try {
            certificate.verify(certificateCA.getPublicKey());
            System.out.println("\tSignature Verification : OK");
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e) {
            System.out.println("\tSignature Verification : KO");
            return false;
        } catch (Exception e) {
            System.out.println("\tSignature Verification : error"+e);
            return false;
        }
    }

    public static void checkCASignature(X509Certificate certificate, String IDCA) throws CertificateException {
        switch (IDCA){
            case "FR01":
                checkSignature(certificate, certificate);
                break;
            case "FR02":
                String certRoot2 = "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";
                checkSignature(certificate, convertStringToX509Cert(certRoot2));
                break;
            case "FR03":
                String certRoot3 = "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";
                checkSignature(certificate, convertStringToX509Cert(certRoot3));
                break;
            case "FR04":
                String certRoot4 = "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";
                checkSignature(certificate, convertStringToX509Cert(certRoot4));
                break;
        }
    }


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////// VERIFY REVOCATION //////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////



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


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////// RETRIEVE TSL INFORMATION /////////////////////////////////////////////
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////



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
