import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.imageio.ImageIO;
import javax.print.Doc;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Info2Ddoc {

    private int headerSize;
    private String message;
    private String signature;
    private String DocType;

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
            System.out.println("[QR code result] " + result.getText()+"\n");
            return result.getText();
        } catch (NotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

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

    public static String getDocType(String header) {
        char[] TabDocType = new char[2];
        header.getChars(20, 22, TabDocType, 0);

        String DocTypeID = String.valueOf(TabDocType);

        switch (DocTypeID){
            case "00":
                return "Justificatif de domicile - Document  émis  spécifiquement  pour servir de justificatif de domicile.";
            case "01":
                return "Justificatif de domicile - Factures de fournisseur d’énergie | Factures de téléphonie| Factures defournisseur d’accès internet | Factures de fournisseur d’eau";
            case "02":
                return "Justificatif de domicile - Avis de taxe d’habitation";
            case "03":
                return "Justificatif  de  domiciliation bancaire - Relevé d’identité bancaire";
            case "05":
                return "Justificatif  de  domiciliation bancaire - Relevé d’Identité SEPAmail";
            case "04":
                return "Justificatif de ressources - Avis d’impôt sur le revenu";
            case "06":
                return "Justificatif de ressources - Bulletin de salaire";
            case "11":
                return "Justificatif de ressources - Relevé de compte";
            case "07":
                return "Justificatif d’identité - Titre d’identité";
            case "08":
                return "Justificatif d’identité - MRZ";
            case "13":
                return "Justificatif d’identité - Document étranger";
            case "09":
                return "Justificatif fiscal - Facture étendue";
            case "10":
                return "Justificatif d’emploi - Contrat de travail";
            case "A0":
                return "Justificatif écologique de véhicule - Certificat de qualité de l’air";
            case "A7":
                return "Justificatif écologique de véhicule - Certificat de qualité de l’air (V2)";
            case "A1":
                return "Justificatif permis de conduire - Courrier Permis à Points";
            case "A2":
                return "Justificatif de santé - Carte Mobilité Inclusion (CMI)";
            case "A3":
                return "Justificatif d’activité - Macaron  VTC (Véhicule  de  Transport avec Chauffeur)";
            case "A5":
                return "Justificatif d’activité - Carte T3P(Transport Public Particulier de Personnes)";
            case "A6":
                return "Justificatif d’activité - Carte Professionnelle Sapeur-Pompier";
            case "A4":
                return "Justificatif médical - Certificat de décès";
            case "B0":
                return "Justificatif académique - Diplôme";
            case "B1":
                return "Justificatif académique - Attestation de Versement de la Contribution à la Vie Etudiante";
            case "12":
                return "Justificatifjuridique/judiciaire - Acte d’huissier";
            case "A8":
                return "Certificat d’immatriculation - Certificat de cession électronique";
            default:
                return "Inconnu (ID:'"+DocTypeID+"')";
        }
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
