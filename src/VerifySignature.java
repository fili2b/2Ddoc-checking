import com.helger.xmldsig.keyselect.X509KeySelector;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.security.PublicKey;

public class VerifySignature {

    public static Document getXmlDocument(String fileName) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory
                .newInstance();
        factory.setNamespaceAware(true);
        File f = new File(fileName);
        if (!f.exists()) {
            throw new IllegalArgumentException("Test data file " + fileName
                    + " not found!");
        }
        // Create the builder and parse the file
        return factory.newDocumentBuilder().parse(f);
    }

    public static boolean isXmlDigitalSignatureValid(String signedXmlFilePath, PublicKey myPubKey) throws Exception {

        boolean validFlag = false;
        Document doc = getXmlDocument(signedXmlFilePath);
        Node sig = null;

        NodeList nodeList = doc.getElementsByTagName("tsl:TrustServiceStatusList");
        for (int i = 0; i < nodeList.getLength(); ++i) {
            Node node = nodeList.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element tElement = (Element) node;
                sig = tElement.getElementsByTagName("ds:Signature").item(0);
            }
        }
        if (nodeList.getLength() == 0) {

            throw new Exception("No XML Digital Signature Found, document is discarded");

        }
        PublicKey publicKey = myPubKey;
        DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), sig);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        validFlag = signature.validate(valContext);
        return validFlag;
    }
}