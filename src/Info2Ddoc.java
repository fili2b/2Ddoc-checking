import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Info2Ddoc {

    private int headerSize;
    private String message;
    private String signature;

    public String getHeader(String data) {
        char[] dataArray = data.toCharArray();
        if (dataArray[3] == '1' || dataArray[3] == '2') {
            char[] header = new char[22];
            data.getChars(0, 22, header, 0);
            this.headerSize = 22;
            return String.valueOf(header);
        } else if (dataArray[3] == '3') {
            char[] header = new char[24];
            data.getChars(0, 22, header, 0);
            this.headerSize = 24;
            return String.valueOf(header);
        } else if (dataArray[3] == '4') {
            char[] header = new char[26];
            data.getChars(0, 26, header, 0);
            this.headerSize = 26;
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

    public String getMessage(String allData) {

        char[] dataWithoutHeader = new char[allData.length()-headerSize];
        allData.getChars(headerSize, allData.length(),dataWithoutHeader,0);
        byte[] dataWithoutHeaderByte = String.valueOf(dataWithoutHeader).getBytes(StandardCharsets.UTF_8);

        int cpt = 0;
        //find the <US> to determine the end of the message
        for (int i = 0; i<dataWithoutHeaderByte.length; i++){
            if(dataWithoutHeaderByte[i] != 31){
                cpt++;
            }
            else {
                break;
            }
        }

        byte[] messageByte = new byte[cpt+1];
        //find the <US> to determine the end of the message
        for (int i = 0; i<dataWithoutHeaderByte.length; i++){
            if(dataWithoutHeaderByte[i] != 31){
                messageByte[i] = dataWithoutHeaderByte[i];
            }
            else{
                break;
            }
        }
        this.message = new String(messageByte, StandardCharsets.UTF_8);
        return this.message;
    }

    public String getSignature(String allData) {

        char[] signature = new char[allData.length()-headerSize-(this.message.length())];
        allData.getChars(headerSize+this.message.length(), allData.length(),signature,0);
        byte[] dataSignatureByte = String.valueOf(signature).getBytes(StandardCharsets.UTF_8);

        int cpt = 0;
        //find the <RS> or <GS> to determine the end of the signature
        for (int i = 0; i<dataSignatureByte.length; i++){
            if(dataSignatureByte[i] != 30 || dataSignatureByte[i] != 29){
                cpt++;
            }
            else {
                break;
            }
        }

        byte[] signatureByte = new byte[cpt+1];
        //find the <RS> or <GS> to determine the end of the signature
        for (int i = 0; i<dataSignatureByte.length; i++){
            if(signatureByte[i] != 30 || signatureByte[i] != 29){
                signatureByte[i] = dataSignatureByte[i];
            }
            else{
                break;
            }
        }
        this.signature = new String(signatureByte, StandardCharsets.UTF_8);
        return this.signature;
    }
}
