import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;

public class Info2Ddoc {

    public static String getHeader(String data) {
        char[] dataArray = data.toCharArray();
        if (dataArray[3] == '1' || dataArray[3] == '2') {
            char[] header = new char[22];
            data.getChars(0, 22, header, 0);
            return String.valueOf(header);
        } else if (dataArray[3] == '3') {
            char[] header = new char[24];
            data.getChars(0, 22, header, 0);
            return String.valueOf(header);
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
}
