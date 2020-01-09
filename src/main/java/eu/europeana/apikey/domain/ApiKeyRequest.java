package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * API-key object as it is defined for incoming requests (e.g. register new key, update a key)
 */
@JsonInclude(NON_EMPTY)
public class ApiKeyRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String appName;
    private String company;
    private String sector;
    private String website;

    public ApiKeyRequest() {
        // empty constructor required for deserializing
    }

    /**
     * Constructor with all required fields
     */
    public ApiKeyRequest(String firstName, String lastName, String email, String appName, String company) {
        this.firstName = firstName;
        this.lastName  = lastName;
        this.email     = email;
        this.appName   = appName;
        this.company   = company;
    }

    /**
     * Constructor with all supported fields
     */
    public ApiKeyRequest(String firstName,
                         String lastName,
                         String email,
                         String appName,
                         String company,
                         String sector,
                         String website) {
        this(firstName, lastName, email, appName, company);
        this.sector  = sector;
        this.website = website;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getEmail() {
        return email;
    }

    public String getAppName() {
        return appName;
    }

    public String getCompany() {
        return company;
    }

    public String getSector() {
        return sector;
    }

    public String getWebsite() {
        return website;
    }
}
