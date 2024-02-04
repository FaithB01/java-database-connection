package org.skyworld.dbconnector;
public class DatabaseConfiguration {
    private String databaseType;
    private String databaseName;
    private String databaseHost;
    private String username;
    private String password;
    private String encryptUsername;
    private String encryptPassword;

    // Constructor
    public DatabaseConfiguration(String databaseType, String databaseName, String databaseHost,
                                 String username, String password, String encryptUsername, String encryptPassword) {
        this.databaseType = databaseType;
        this.databaseName = databaseName;
        this.databaseHost = databaseHost;
        this.username = username;
        this.password = password;
        this.encryptUsername = encryptUsername;
        this.encryptPassword = encryptPassword;
    }

    // Getters and Setters

    public String getDatabaseType() {
        return databaseType;
    }

    public void setDatabaseType(String databaseType) {
        this.databaseType = databaseType;
    }

    public String getDatabaseName() {
        return databaseName;
    }

    public void setDatabaseName(String databaseName) {
        this.databaseName = databaseName;
    }

    public String getDatabaseHost() {
        return databaseHost;
    }

    public void setDatabaseHost(String databaseHost) {
        this.databaseHost = databaseHost;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEncryptUsername() {
        return encryptUsername;
    }

    public void setEncryptUsername(String encryptUsername) {
        this.encryptUsername = encryptUsername;
    }

    public String getEncryptPassword() {
        return encryptPassword;
    }

    public void setEncryptPassword(String encryptPassword) {
        this.encryptPassword = encryptPassword;
    }
    public String getJdbcDriver() {
        switch (databaseType) {
            case "MySQL":
                return "com.mysql.cj.jdbc.Driver";
            case "PostgreSQL":
                return "org.postgresql.Driver";
            case "MicrosoftSQL":
                return "com.microsoft.sqlserver.jdbc.SQLServerDriver";
            default:
                throw new IllegalArgumentException("Unsupported database type: " + databaseType);
        }
    }
}
