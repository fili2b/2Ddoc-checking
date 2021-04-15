import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DisplayInfo {
    private List<Triple> idList = new ArrayList<Triple>();
    private Integer indice = 0;


    DisplayInfo() {
        setTupleList();
    }

    public void setTupleList() {
        this.idList.add(new Triple("01", "Identifiant unique du document", null));
        this.idList.add(new Triple("02", "Catégorie de document", null));
        this.idList.add(new Triple("03", "Sous-catégorie de document", null));
        this.idList.add(new Triple("04", "Application de composition", null));
        this.idList.add(new Triple("05", "Version de l’application de composition", null));
        this.idList.add(new Triple("06", "Date de l’association entre le document et le code 2D-Doc", 4));
        this.idList.add(new Triple("07", "Heure de l’association entre le document et le code 2D-Doc", 6));
        this.idList.add(new Triple("08", "Date d’expiration du document", 4));
        this.idList.add(new Triple("09", "Nombre de pages du document", 4));
        this.idList.add(new Triple("0A", "Editeur du 2D-Doc", 9));
        this.idList.add(new Triple("0B", "Intégrateur du 2D-Doc", 9));
        this.idList.add(new Triple("0C", "URL du document", null));
        this.idList.add(new Triple("10", "Ligne 1 de la norme adresse postale du bénéficiaire de la prestation", null));
        this.idList.add(new Triple("11", "Qualité et/ou titre de la personne bénéficiaire de la prestation", null));
        this.idList.add(new Triple("12", "Prénom de la personne bénéficiaire de la prestation", null));
        this.idList.add(new Triple("13", "Nom de la personne bénéficiaire de la prestation", null));
        this.idList.add(new Triple("14", "Ligne 1 de la norme adresse postale du destinataire de la facture", null));
        this.idList.add(new Triple("15", "Qualité et/ou titre de la personne destinataire de la facture", null));
        this.idList.add(new Triple("16", "Prénom de la personne destinataire de la facture", null));
        this.idList.add(new Triple("17", "Nom de la personne destinataire de la facture", null));
        this.idList.add(new Triple("18", "Numéro de la facture", null));
        this.idList.add(new Triple("19", "Numéro de client", null));
        this.idList.add(new Triple("1A", "Numéro du contrat", null));
        this.idList.add(new Triple("1B", "Identifiant du souscripteur du contrat", null));
        this.idList.add(new Triple("1C", "Date d’effet du contrat", 8));
        this.idList.add(new Triple("1D", "Montant TTC de la facture", null));
        this.idList.add(new Triple("1E", "Numéro de téléphone du bénéficiaire de la prestation", null));
        this.idList.add(new Triple("1F", "Numéro de téléphone du destinataire de la facture", null));
        this.idList.add(new Triple("1G", "Présence d’un co-bénéficiaire de la prestation non mentionné dans le code", 1));
        this.idList.add(new Triple("1H", "Présence d’un co-destinataire de la facture non mentionné dans le code", 1));
        this.idList.add(new Triple("1I", "Ligne 1 de la norme adresse postale du co-bénéficiaire de la prestation", null));
        this.idList.add(new Triple("1J", "Qualité et/ou titre de la personne co-bénéficiaire de la prestation", null));
        this.idList.add(new Triple("1K", "Prénom de la personne co-bénéficiaire de la prestation", null));
        this.idList.add(new Triple("1L", "Nom de la personne co-bénéficiaire de la prestation", null));
        this.idList.add(new Triple("1M", "Ligne 1 de la norme adresse postale du co-destinataire de la facture", null));
        this.idList.add(new Triple("1N", "Qualité et/ou titre du co-destinataire de la facture", null));
        this.idList.add(new Triple("1O", "Prénom du co-destinataire de la facture", null));
        this.idList.add(new Triple("1P", "Nom du co-destinataire de la facture", null));
        this.idList.add(new Triple("20", "Ligne 2 de la norme adresse postale du point de service des prestations", null));
        this.idList.add(new Triple("21", "Ligne 3 de la norme adresse postale du point de service des prestations", null));
        this.idList.add(new Triple("22", "Ligne 4 de la norme adresse postale du point de service des prestations", null));
        this.idList.add(new Triple("23", "Ligne 5 de la norme adresse postale du point de service des prestations", null));
        this.idList.add(new Triple("24", "Code postal ou code cedex du point de service des prestations", 5));
        this.idList.add(new Triple("25", "Localité de destination ou libellé cedex du point de service des prestations", null));
        this.idList.add(new Triple("26", "Pays de service des prestations", 2));
        this.idList.add(new Triple("27", "Ligne 2 de la norme adresse postale du destinataire de la facture", null));
        this.idList.add(new Triple("28", "Ligne 3 de la norme adresse postale du destinataire de la facture", null));
        this.idList.add(new Triple("29", "Ligne 4 de la norme adresse postale du destinataire de la facture", null));
        this.idList.add(new Triple("2A", "Ligne 5 de la norme adresse postale du destinataire de la facture", null));
        this.idList.add(new Triple("2B", "Code postal ou code cedex du destinataire de la facture", 5));
        this.idList.add(new Triple("2C", "Localité de destination ou libellé cedex du destinataire de la facture", null));
        this.idList.add(new Triple("2D", "Pays du destinataire de la facture", 2));
        this.idList.add(new Triple("30", "Qualité Nom et Prénom", null));
        this.idList.add(new Triple("31", "Code IBAN", null));
        this.idList.add(new Triple("32", "Code BIC/SWIFT", null));
        this.idList.add(new Triple("33", "Code BBAN", null));
        this.idList.add(new Triple("34", "Pays de localisation du compte", 2));
        this.idList.add(new Triple("35", "Identifiant SEPAmail this.idList.add(new Triple(QXBAN))", null));
        this.idList.add(new Triple("36", "Date de début de période", 4));
        this.idList.add(new Triple("37", "Date de fin de période", 4));
        this.idList.add(new Triple("38", "Solde compte début de période", null));
        this.idList.add(new Triple("39", "Solde compte fin de période", null));
        this.idList.add(new Triple("1N", "", null));
        this.idList.add(new Triple("40", "Numéro fiscal", 13));
        this.idList.add(new Triple("41", "Revenu fiscal de référence", null));
        this.idList.add(new Triple("42", "Situation du foyer", null));
        this.idList.add(new Triple("43", "Nombre de parts", null));
        this.idList.add(new Triple("44", "Référence d’avis d’impôt", 13));
        this.idList.add(new Triple("50", "SIRET de l’employeur", 14));
        this.idList.add(new Triple("51", "Nombre d’heures travaillées", 6));
        this.idList.add(new Triple("52", "Cumul du nombre d’heures travaillées", 7));
        this.idList.add(new Triple("53", "Début de période", 4));
        this.idList.add(new Triple("54", "Fin de période", 4));
        this.idList.add(new Triple("55", "Date de début de contrat", 8));
        this.idList.add(new Triple("56", "Date de fin de contrat", 4));
        this.idList.add(new Triple("57", "Date de signature du contrat", 8));
        this.idList.add(new Triple("58", "Salaire net imposable", null));
        this.idList.add(new Triple("59", "", null));
        this.idList.add(new Triple("5A", "Salaire brut du mois", null));
        this.idList.add(new Triple("5B", "Cumul du salaire brut", null));
        this.idList.add(new Triple("5C", "Salaire net", null));
        this.idList.add(new Triple("5D", "Ligne 2 de la norme adresse postale de l’employeur", null));
        this.idList.add(new Triple("5E", "Ligne 3 de la norme adresse postale de l’employeur", null));
        this.idList.add(new Triple("5F", "Ligne 4 de la norme adresse postale de l’employeur", null));
        this.idList.add(new Triple("5G", "Ligne 5 de la norme adresse postale de l’employeur", null));
        this.idList.add(new Triple("5H", "Code postal ou code cedex de l’employeur", 5));
        this.idList.add(new Triple("5I", "Localité de destination ou libellé cedex de l’employeur", null));
        this.idList.add(new Triple("5J", "Pays de l’employeur", 2));
        this.idList.add(new Triple("5K", "Identifiant Cotisant Prestations Sociales", null));
        this.idList.add(new Triple("60", "Liste des prénoms", null));
        this.idList.add(new Triple("61", "Prénom", null));
        this.idList.add(new Triple("62", "Nom patronymique", null));
        this.idList.add(new Triple("63", "Nom d’usage", null));
        this.idList.add(new Triple("64", "Nom d’épouse/époux", null));
        this.idList.add(new Triple("65", "Type de pièce d’identité", 2));
        this.idList.add(new Triple("66", "Numéro de la pièce d’identité", null));
        this.idList.add(new Triple("67", "Nationalité", 2));
        this.idList.add(new Triple("68", "Genre", 1));
        this.idList.add(new Triple("69", "Date de naissance", 8));
        this.idList.add(new Triple("6A", "Lieu de naissance", null));
        this.idList.add(new Triple("6B", "Département du bureau émetteur", 3));
        this.idList.add(new Triple("6C", "Pays de naissance", 2));
        this.idList.add(new Triple("6D", "Nom et prénom du père", null));
        this.idList.add(new Triple("6E", "Nom et prénom de la mère", null));
        this.idList.add(new Triple("6F", "Machine Readable Zone this.idList.add(new Triple(Zone de Lecture Automatique, ZLA))", null));
        this.idList.add(new Triple("6G", "Nom", null));
        this.idList.add(new Triple("6H", "Civilité", null));
        this.idList.add(new Triple("6I", "Pays émetteur", 2));
        this.idList.add(new Triple("6J", "Type de document étranger", 1));
        this.idList.add(new Triple("6K", "Numéro de la demandede document étranger", 19));
        this.idList.add(new Triple("6L", "Date de dépôt de la demande", 8));
        this.idList.add(new Triple("6M", "Catégorie du titre", null));
        this.idList.add(new Triple("6N", "Date de début de validité", 8));
        this.idList.add(new Triple("6O", "Date de fin de validité", 8));
        this.idList.add(new Triple("6P", "Autorisation", null));
        this.idList.add(new Triple("6Q", "Numéro d’étranger", null));
        this.idList.add(new Triple("6R", "Numéro de visa", 12));
        this.idList.add(new Triple("6S", "Ligne 2 de l'adresse postale du domicile", null));
        this.idList.add(new Triple("6T", "Ligne 3 de l'adresse postale du domicile", null));
        this.idList.add(new Triple("6U", "Ligne 4 de l'adresse postale du domicile", null));
        this.idList.add(new Triple("6V", "Ligne 5 de l'adresse postale du domicile", null));
        this.idList.add(new Triple("6W", "Code postal ou code cedex de l'adresse postale du domicile", 5));
        this.idList.add(new Triple("6X", "Commune de l'adresse postale du domicile", null));
        this.idList.add(new Triple("6Y", "Code pays de l'adresse postale du domicile", 2));
        this.idList.add(new Triple("70", "Date et heure du décès", 12));
        this.idList.add(new Triple("71", "Date et heure du constat de décès", 12));
        this.idList.add(new Triple("72", "Nom du défunt", null));
        this.idList.add(new Triple("73", "Prénoms du défunt", null));
        this.idList.add(new Triple("74", "Nom de jeune filledu défunt", null));
        this.idList.add(new Triple("75", "Date de naissance du défunt", 8));
        this.idList.add(new Triple("76", "Genre du défunt", 1));
        this.idList.add(new Triple("77", "Commune dedécès", null));
        this.idList.add(new Triple("78", "Code postal de la commune de décès", 5));
        this.idList.add(new Triple("79", "Adresse du domicile du défunt", null));
        this.idList.add(new Triple("7A", "Code postal du domicile du défunt", 5));
        this.idList.add(new Triple("7B", "Commune du domicile du défunt", null));
        this.idList.add(new Triple("7C", "Obstacle médico-légal", 1));
        this.idList.add(new Triple("7D", "Mise en bière", 1));
        this.idList.add(new Triple("7E", "Obstacle aux soins de conservation", 1));
        this.idList.add(new Triple("7F", "Obstacle aux dons du corps", 1));
        this.idList.add(new Triple("7G", "Recherche de la cause du décès", 1));
        this.idList.add(new Triple("7H", "Délai de transport du corps", 2));
        this.idList.add(new Triple("7I", "Prothèse avec pile", 1));
        this.idList.add(new Triple("7J", "Retrait de la pile de prothèse", 1));
        this.idList.add(new Triple("7K", "Code NNC", 13));
        this.idList.add(new Triple("7L", "Code Finess de l'organisme agréé", 9));
        this.idList.add(new Triple("7M", "Identification du médecin", null));
        this.idList.add(new Triple("7N", "Lieu de validation du certificat de décès", null));
        this.idList.add(new Triple("7O", "Certificat de décès supplémentaire", 1));
        this.idList.add(new Triple("80", "Nom", null));
        this.idList.add(new Triple("81", "Prénoms", null));
        this.idList.add(new Triple("82", "Numéro de carte", null));
        this.idList.add(new Triple("83", "Organisme de tutelle", null));
        this.idList.add(new Triple("84", "Profession", null));
        this.idList.add(new Triple("90", "Identité de l'huissier de justice", null));
        this.idList.add(new Triple("91", "Identité ou raison sociale du demandeur", null));
        this.idList.add(new Triple("92", "Identité ou raison sociale du destinataire", null));
        this.idList.add(new Triple("93", "Identité ou raison sociale de tiers concerné", null));
        this.idList.add(new Triple("94", "Intitulé de l'acte", null));
        this.idList.add(new Triple("95", "Numéro de l'acte", null));
        this.idList.add(new Triple("96", "Date de signature de l'acte", 8));
        this.idList.add(new Triple("A0", "Pays ayant émis l’immatriculation du véhicule.", 2));
        this.idList.add(new Triple("A1", "Immatriculation du véhicule", null));
        this.idList.add(new Triple("A2", "Marque du véhicule.", null));
        this.idList.add(new Triple("A3", "Nom commercial du véhicule", null));
        this.idList.add(new Triple("A4", "Numéro de série du véhicule this.idList.add(new Triple(VIN)).", 17));
        this.idList.add(new Triple("A5", "Catégorie du véhicule.", 1));
        this.idList.add(new Triple("A6", "Carburant", 2));
        this.idList.add(new Triple("A7", "Taux d’émission de CO2 du véhicule this.idList.add(new Triple(en g/km)).", 3));
        this.idList.add(new Triple("A8", "Indication de la classe environnementale de réception CE.", null));
        this.idList.add(new Triple("A9", "Classe d’émission polluante.", 3));
        this.idList.add(new Triple("AA", "Date de première immatriculation du véhicule.", 8));
        this.idList.add(new Triple("AB", "Type de lettre", null));
        this.idList.add(new Triple("AC", "N° Dossier", null));
        this.idList.add(new Triple("AD", "Date Infraction", 4));
        this.idList.add(new Triple("AE", "Heure de l’infraction", 4));
        this.idList.add(new Triple("AF", "Nombre de points  retirés lors de l’infraction", 1));
        this.idList.add(new Triple("AG", "Solde de points", 1));
        this.idList.add(new Triple("AH", "Numéro de la carte", null));
        this.idList.add(new Triple("AI", "Date d’expiration initiale", 8));
        this.idList.add(new Triple("AJ", "Numéro EVTC", 13));
        this.idList.add(new Triple("AK", "Numéro de macaron", 7));
        this.idList.add(new Triple("AL", "Numéro de la carte", 11));
        this.idList.add(new Triple("AM", "Motif de sur-classement", null));
        this.idList.add(new Triple("AN", "Kilométrage", 8));
        this.idList.add(new Triple("B0", "Liste des prénoms", null));
        this.idList.add(new Triple("B1", "Prénom", null));
        this.idList.add(new Triple("B2", "Nom patronymique", null));
        this.idList.add(new Triple("B3", "Nom d'usage", null));
        this.idList.add(new Triple("B4", "Nom d'épouse/époux ", null));
        this.idList.add(new Triple("B5", "Nationalité ", 2));
        this.idList.add(new Triple("B6", "Genre ", 1));
        this.idList.add(new Triple("B7", "Date de naissance ", 8));
        this.idList.add(new Triple("B8", "Lieu de naissance ", null));
        this.idList.add(new Triple("B9", "Pays de naissance ", 2));
        this.idList.add(new Triple("BA", "Mention obtenue ", 1));
        this.idList.add(new Triple("BB", "Numéro ou code d'identification de l'étudiant ", null));
        this.idList.add(new Triple("BC", "Numéro du diplôme ", null));
        this.idList.add(new Triple("BD", "Niveau du diplôme selon la classification CEC ", 1));
        this.idList.add(new Triple("BE", "Crédits ECTS obtenus ", 3));
        this.idList.add(new Triple("BF", "Année universitaire ", 3));
        this.idList.add(new Triple("BG", "Type de diplôme ", 2));
        this.idList.add(new Triple("BH", "Domaine ", null));
        this.idList.add(new Triple("BI", "Mention ", null));
        this.idList.add(new Triple("BJ", "Spécialité ", null));
        this.idList.add(new Triple("BK", "Numérode l'Attestation de versement dela CVE", 14));
        this.idList.add(new Triple("C0", "Genre du vendeur", 1));
        this.idList.add(new Triple("C1", "Nom patronymique du vendeur", null));
        this.idList.add(new Triple("C2", "Prénom du vendeur", null));
        this.idList.add(new Triple("C3", "Date et heure de la cession", 12));
        this.idList.add(new Triple("C4", "Date de la signature du vendeur", 8));
        this.idList.add(new Triple("C5", "Genre de l’acheteur", 1));
        this.idList.add(new Triple("C6", "Nom patronymique de l’acheteur", null));
        this.idList.add(new Triple("C7", "Prénom de l’acheteur", null));
        this.idList.add(new Triple("C8", "Ligne 4 de la norme adresse postale du domicile de l’acheteur", null));
        this.idList.add(new Triple("C9", "Code postal ou code cedex du domicile de l’acheteur", 5));
        this.idList.add(new Triple("CertificateManage", "Commune du domicile de l’acheteur", null));
        this.idList.add(new Triple("CB", "CN° d’enregistrement", 10));
        this.idList.add(new Triple("CC", "Date et heure d'enregistrement dans le SIV", 12));
    }

    void printMessageInfo(String message) {
        byte[] messageByte = message.getBytes(StandardCharsets.UTF_8);
        System.out.println("[2D doc Information]");
        for (this.indice=0; this.indice < messageByte.length; this.indice++) {
            if(this.indice != 0)
                this.indice--;
            switch(messageByte[this.indice]) {
                case 29:
                    this.indice += 1;
                    break;
                case 30:
                    this.indice += 1;
                    break;
                case 31:
                    this.indice += 1;
                    break;
                default:
                    byte[] test = new byte[2];
                    System.arraycopy(messageByte, this.indice, test, 0, 2);
                    String maVar = new String(test, StandardCharsets.UTF_8);
                    for (Triple j : this.idList) {
                        if (maVar.equals(j.getFirst().toString())) {
                            this.indice += 2;
                            System.out.println("\t- " + j.getSecond() + " : " + getData(j, messageByte));
                        }
                    }
                    break;
            }
        }
    }

    String getData(Triple triplet, byte[] mes) {
        byte[] data = new byte[128];
        int i = 0;
        if (triplet.getThird() == null) {
            for(int j = 0; j < mes.length; j++) {
                switch(mes[this.indice]) {
                    case 29:
                        break;
                    case 30:
                        break;
                    case 31:
                        break;
                    default:
                        data[i] = mes[this.indice];
                        i += 1;
                        this.indice += 1;
                }
            }
            byte[] newData = new byte[i];
            System.arraycopy(data, 0, newData, 0, i);
            return new String(newData, StandardCharsets.UTF_8);
        } else {
            byte[] newData = new byte[(Integer) triplet.getThird()];
            for (int j = 0; j < (Integer) triplet.getThird(); j++) {
                newData[j] = mes[this.indice];
                this.indice+=1;
            }
            return new String(newData, StandardCharsets.UTF_8);
        }
    }
}
