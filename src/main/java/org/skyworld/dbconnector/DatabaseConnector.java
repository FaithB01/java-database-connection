package org.skyworld.dbconnector;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.Base64;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;


public class DatabaseConnector {

    public static void main(String[] args) {
        try {
            // Load the configuration from XML file
            DatabaseConfiguration configuration = loadConfiguration("C:\\Users\\BKT\\Desktop\\PROJECTS\\JAVA\\DBconnect\\config.xml");

            // Connect to the database
            Connection connection = connectToDatabase(configuration);

            // Perform database operations using the 'connection' object as needed
            performDatabaseOperations(connection);

            // Close the database connection
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

////        keygenrator//
        try {
            // Generate a secure random 256-bit (32-byte) key
            SecretKey secretKey = generateAESKey();

            // Convert the key to a Base64-encoded string for storage or transmission
            String base64Key = Base64.getEncoder().encodeToString(secretKey.getEncoded());

//            System.out.println("Generated AES Key: " + base64Key);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    //key generator function//
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // 256 bits for AES-256
        return keyGenerator.generateKey();
    }
    private static void performDatabaseOperations(Connection connection) throws Exception {
        System.out.println("*******************EXAM SET****************************" );
        // Execute a SELECT query
        String sql = "        SELECT t.*\n" +
                "        FROM o_exam.exam_set t\n" +
                "        LIMIT 501";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
            // Execute the query
            ResultSet resultSet = preparedStatement.executeQuery();

            // Process the results
            while (resultSet.next()) {
                int id = resultSet.getInt("exam_id");
                String name = resultSet.getString("exam_name");
                String firstName = resultSet.getString("first_name");
                String lastName = resultSet.getString("last_name");
                String subjectName = resultSet.getString("subject_name");
                System.out.println("exam_id: " + id + ", exam_name: " + name+" , first_name " + firstName + ", last_name: " + lastName+" , subject_name: " + subjectName);

            }
        }
        System.out.println("*******************EXAM SET****************************" );
        System.out.println("*******************Answer Provided by a pupil****************************" );
        String answer = "SELECT t.*\n" +
                "        FROM o_exam.answers_provided t\n" +
                "        LIMIT 501";
        try (PreparedStatement preparedStatement = connection.prepareStatement(answer)) {
            // Execute the query
            ResultSet resultSet = preparedStatement.executeQuery();

            // Process the results
            while (resultSet.next()) {
                // Retrieve data from the result set
                int id = resultSet.getInt("teacher_id");
                String name = resultSet.getString("first_name");
                // Process the retrieved data as needed
                System.out.println("teacher_id: " + id + ", first_name: " + name);

            }
        }
        System.out.println("*******************Answer Provided by a pupil****************************" );
        System.out.println("*******************TOP FIVE****************************" );
        // Example: Execute a SELECT query
        String top = "SELECT * FROM teachers";
        try (PreparedStatement preparedStatement = connection.prepareStatement(top)) {
            // Execute the query
            ResultSet resultSet = preparedStatement.executeQuery();

            // Process the results
            while (resultSet.next()) {
                // Retrieve data from the result set
                int id = resultSet.getInt("teacher_id");
                String name = resultSet.getString("first_name");
                // Process the retrieved data as needed
                System.out.println("teacher_id: " + id + ", first_name: " + name);

            }
        }
        System.out.println("*******************TOP FIVE****************************" );
        System.out.println("*******************HIGHEST TO THE LOWEST****************************" );
        // Example: Execute a SELECT query
        String highest = "SELECT * FROM teachers";
        try (PreparedStatement preparedStatement = connection.prepareStatement(highest)) {
            // Execute the query
            ResultSet resultSet = preparedStatement.executeQuery();

            // Process the results
            while (resultSet.next()) {
                // Retrieve data from the result set
                int id = resultSet.getInt("teacher_id");
                String name = resultSet.getString("first_name");
                // Process the retrieved data as needed
                System.out.println("teacher_id: " + id + ", first_name: " + name);

            }
        }
        System.out.println("*******************HIGHEST TO THE LOWEST****************************" );
    }
    private static DatabaseConfiguration loadConfiguration(String filePath) throws Exception {
        File file = new File(filePath);

        // Read XML file
        String xmlContent = new String(java.nio.file.Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);

        // Update username and password elements
        xmlContent = updateCredentials(xmlContent);


        // Parse XML to a DatabaseConfiguration object

        return parseXmlToConfiguration(xmlContent);
    }


//    private static String updateCredentials(String xmlContent) throws Exception {
//        // Parse XML content and update credentials
//        String updatedXmlContent = xmlContent;
//
//        // Get the username element and check if it needs to be encrypted
//        String usernameStartTag = "<username ENCRYPTED=\"";
//        String usernameEndTag = "</username>";
//        int usernameStartIndex = updatedXmlContent.indexOf(usernameStartTag);
//        while (usernameStartIndex != -1) {
//            int usernameEndIndex = updatedXmlContent.indexOf("\"", usernameStartIndex + usernameStartTag.length());
//            String encryptedAttribute = updatedXmlContent.substring(usernameStartIndex + usernameStartTag.length(), usernameEndIndex);
//            String usernameValue = updatedXmlContent.substring(usernameEndIndex + 2, updatedXmlContent.indexOf(usernameEndTag, usernameEndIndex));
//
//            if ("NO".equals(encryptedAttribute)) {
//                // Encrypt the username value
//                String encryptedUsername = encrypt(usernameValue);
//                updatedXmlContent = updatedXmlContent.substring(0, usernameEndIndex + 2) + encryptedUsername + updatedXmlContent.substring(updatedXmlContent.indexOf(usernameEndTag, usernameEndIndex));
//            }
//
//            usernameStartIndex = updatedXmlContent.indexOf(usernameStartTag, usernameEndIndex);
//
//        }
//
//        // Get the password element and check if it needs to be encrypted
//        String passwordStartTag = "<password ENCRYPTED=\"";
//        String passwordEndTag = "</password>";
//        int passwordStartIndex = updatedXmlContent.indexOf(passwordStartTag);
//        while (passwordStartIndex != -1) {
//            int passwordEndIndex = updatedXmlContent.indexOf("\"", passwordStartIndex + passwordStartTag.length());
//            String encryptedAttribute = updatedXmlContent.substring(passwordStartIndex + passwordStartTag.length(), passwordEndIndex);
//            String passwordValue = updatedXmlContent.substring(passwordEndIndex + 2, updatedXmlContent.indexOf(passwordEndTag, passwordEndIndex));
//
//            if ("NO".equals(encryptedAttribute)) {
//                // Encrypt the password value
//                String encryptedPassword = encrypt(passwordValue);
//                updatedXmlContent = updatedXmlContent.substring(0, passwordEndIndex + 2) + encryptedPassword + updatedXmlContent.substring(updatedXmlContent.indexOf(passwordEndTag, passwordEndIndex));
//            }
//
//            passwordStartIndex = updatedXmlContent.indexOf(passwordStartTag, passwordEndIndex);
//        }
//        Files.write(Paths.get("C:\\Users\\BKT\\Desktop\\PROJECTS\\JAVA\\DBconnect\\config.xml"), updatedXmlContent.getBytes());
//        System.out.println("Encrypted Password" + updatedXmlContent);
//        return updatedXmlContent;
//         }

//    ------------------------------------------------WRITTEN XML VERSION__________________________________________________________//
//    private static String updateCredentials(String xmlContent) throws Exception {
//        // Parse XML content and update credentials
//        String updatedXmlContent = xmlContent;
//
//        // Get the username element and check if it needs to be encrypted
//        String usernameStartTag = "<username ENCRYPTED=\"";
//        String usernameEndTag = "</username>";
//        int usernameStartIndex = updatedXmlContent.indexOf(usernameStartTag);
//        while (usernameStartIndex != -1) {
//            int usernameEndIndex = updatedXmlContent.indexOf("\"", usernameStartIndex + usernameStartTag.length());
//            String encryptedAttribute = updatedXmlContent.substring(usernameStartIndex + usernameStartTag.length(), usernameEndIndex);
//            String usernameValue = updatedXmlContent.substring(usernameEndIndex + 2, updatedXmlContent.indexOf(usernameEndTag, usernameEndIndex));
//
//            if ("NO".equals(encryptedAttribute)) {
//                // Encrypt the username value
//                String encryptedUsername = encrypt(usernameValue);
//                updatedXmlContent = updatedXmlContent.substring(0, usernameEndIndex + 2) + encryptedUsername + updatedXmlContent.substring(updatedXmlContent.indexOf(usernameEndTag, usernameEndIndex));
//            }
//
//            usernameStartIndex = updatedXmlContent.indexOf(usernameStartTag, usernameEndIndex);
//        }
//
//        // Get the password element and check if it needs to be encrypted
//        String passwordStartTag = "<password ENCRYPTED=\"";
//        String passwordEndTag = "</password>";
//        int passwordStartIndex = updatedXmlContent.indexOf(passwordStartTag);
//        while (passwordStartIndex != -1) {
//            int passwordEndIndex = updatedXmlContent.indexOf("\"", passwordStartIndex + passwordStartTag.length());
//            String encryptedAttribute = updatedXmlContent.substring(passwordStartIndex + passwordStartTag.length(), passwordEndIndex);
//            String passwordValue = updatedXmlContent.substring(passwordEndIndex + 2, updatedXmlContent.indexOf(passwordEndTag, passwordEndIndex));
//
//            if ("NO".equals(encryptedAttribute)) {
//                // Encrypt the password value
//                String encryptedPassword = encrypt(passwordValue);
//                updatedXmlContent = updatedXmlContent.substring(0, passwordEndIndex + 2) + encryptedPassword + updatedXmlContent.substring(updatedXmlContent.indexOf(passwordEndTag, passwordEndIndex));
//            }
//
//            passwordStartIndex = updatedXmlContent.indexOf(passwordStartTag, passwordEndIndex);
//        }
//        // Write the updated XML content back to the file
////        Files.write(Paths.get("C:\\Users\\BKT\\Desktop\\PROJECTS\\JAVA\\DBconnect\\config.xml"), updatedXmlContent.getBytes());
//
//        System.out.println("Encrypted Password: " + updatedXmlContent);
//        return updatedXmlContent;
//    }


    private static String updateCredentials(String xmlContent) throws Exception {
        // Parse XML content and update credentials
        String updatedXmlContent = xmlContent;

        // Get the username element and check if it needs to be encrypted
        String usernameStartTag = "<username ENCRYPTED=\"";
        String usernameEndTag = "</username>";
        int usernameStartIndex = updatedXmlContent.indexOf(usernameStartTag);
        while (usernameStartIndex != -1) {
            int usernameEndIndex = updatedXmlContent.indexOf("\"", usernameStartIndex + usernameStartTag.length());
            String encryptedAttribute = updatedXmlContent.substring(usernameStartIndex + usernameStartTag.length(), usernameEndIndex);
            String usernameValue = updatedXmlContent.substring(usernameEndIndex + 2, updatedXmlContent.indexOf(usernameEndTag, usernameEndIndex));

            if ("NO".equals(encryptedAttribute)) {
                // Encrypt the username value
                String encryptedUsername = encrypt(usernameValue);
                updatedXmlContent = updatedXmlContent.substring(0, usernameEndIndex + 2) + encryptedUsername + updatedXmlContent.substring(updatedXmlContent.indexOf(usernameEndTag, usernameEndIndex));
            }

            usernameStartIndex = updatedXmlContent.indexOf(usernameStartTag, usernameEndIndex);
        }

        // Get the password element and check if it needs to be encrypted
        String passwordStartTag = "<password ENCRYPTED=\"";
        String passwordEndTag = "</password>";
        int passwordStartIndex = updatedXmlContent.indexOf(passwordStartTag);
        while (passwordStartIndex != -1) {
            int passwordEndIndex = updatedXmlContent.indexOf("\"", passwordStartIndex + passwordStartTag.length());
            String encryptedAttribute = updatedXmlContent.substring(passwordStartIndex + passwordStartTag.length(), passwordEndIndex);
            String passwordValue = updatedXmlContent.substring(passwordEndIndex + 2, updatedXmlContent.indexOf(passwordEndTag, passwordEndIndex));

            if ("NO".equals(encryptedAttribute)) {
                // Encrypt the password value
                String encryptedPassword = encrypt(passwordValue);
                updatedXmlContent = updatedXmlContent.substring(0, passwordEndIndex + 2) + encryptedPassword + updatedXmlContent.substring(updatedXmlContent.indexOf(passwordEndTag, passwordEndIndex));
            }

            passwordStartIndex = updatedXmlContent.indexOf(passwordStartTag, passwordEndIndex);
        }
        // Write the updated XML content back to the file
        Files.write(Paths.get("C:\\Users\\BKT\\Desktop\\PROJECTS\\JAVA\\DBconnect\\config.xml"), updatedXmlContent.getBytes());

        System.out.println("Encrypted Password: " + updatedXmlContent);
        return updatedXmlContent;
    }

    //-----------------------------------------------------------------------------------------------------------------------------------//
private static DatabaseConfiguration parseXmlToConfiguration(String xmlContent) {
    try {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();

        // Parse the XML content
        Document document = builder.parse(new InputSource(new StringReader(xmlContent)));

        // Get the root element
        Element root = document.getDocumentElement();

        // Get child nodes and set properties in DatabaseConfiguration object
        String databaseType = getTextContent(root, "databaseType");
        String databaseName = getTextContent(root, "databaseName");
        String databaseHost = getTextContent(root, "databaseHost");
        String username = getTextContent(root, "username");
        String password = getTextContent(root, "password");
        String encryptUsername = getAttribute(root, "username", "ENCRYPTED");
        String encryptPassword = getAttribute(root, "password", "ENCRYPTED");

        return new DatabaseConfiguration(databaseType, databaseName, databaseHost, username, password, encryptUsername, encryptPassword);

    } catch (Exception e) {
        e.printStackTrace();
        return null; // Handle the exception appropriately in your application
    }
}

    private static String getTextContent(Element element, String tagName) {
        NodeList nodeList = element.getElementsByTagName(tagName);
        if (nodeList.getLength() > 0) {
            Node node = nodeList.item(0);
            return node.getTextContent();
        }
        return null;
    }

    private static String getAttribute(Element element, String tagName, String attributeName) {
        NodeList nodeList = element.getElementsByTagName(tagName);
        if (nodeList.getLength() > 0) {
            Node node = nodeList.item(0);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element elementNode = (Element) node;
                return elementNode.getAttribute(attributeName);
            }
        }
        return null;
    }


    //---------------------------------------------------------------------------------------------------------------------------------------------//
    private static Connection connectToDatabase(DatabaseConfiguration configuration) throws SQLException {
        String url = buildDatabaseUrl(configuration);

        // Load JDBC driver (depending on the database type)
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");

//            Class.forName(configuration.getJdbcDriver());
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Failed to load JDBC driver", e);
        }

        // Connect to the database
        return DriverManager.getConnection(url, configuration.getUsername(), configuration.getPassword());
    }


    private static String buildDatabaseUrl(DatabaseConfiguration configuration) {
        String databaseType = configuration.getDatabaseType().toLowerCase();
        String databaseHost = configuration.getDatabaseHost();
        String databaseName = configuration.getDatabaseName();

        switch (databaseType) {
            case "mysql":
                return String.format("jdbc:mysql://172.20.94.32/o_exam", databaseHost, databaseName);
            case "postgresql":
                return String.format("jdbc:postgresql://%s/%s", databaseHost, databaseName);
            case "microsoftsql":
                return String.format("jdbc:sqlserver://%s;databaseName=%s", databaseHost, databaseName);
            default:
                throw new IllegalArgumentException("Unsupported database type: " + databaseType);
        }
    }

    private static String encrypt(String value) throws Exception {
        // Generate a secure random 256-bit (32-byte) key
        SecretKey keysecret = generateAESKey();

        // Convert the key to a Base64-encoded string for storage or transmission
        String base64Key = Base64.getEncoder().encodeToString(keysecret.getEncoded());
        String encryptionKey = base64Key; // Replace with a strong key
//        SecretKey secretKey = new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keysecret);
        byte[] encryptedBytes = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encrypted succesfully");

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
  }

