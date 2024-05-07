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

    /**
     * Instantiates a new Api key request.
     */
    public ApiKeyRequest() {
        // empty constructor required for deserializing
    }

    /**
     * Constructor with all required fields
     *
     * @param firstName the first name
     * @param lastName  the last name
     * @param email     the email
     * @param appName   the app name
     * @param company   the company
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
     *
     * @param firstName the first name
     * @param lastName  the last name
     * @param email     the email
     * @param appName   the app name
     * @param company   the company
     * @param sector    the sector
     * @param website   the website
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

    /**
     * Gets first name.
     *
     * @return the first name
     */
    public String getFirstName() {
        return firstName;
    }

    /**
     * Gets last name.
     *
     * @return the last name
     */
    public String getLastName() {
        return lastName;
    }

    /**
     * Gets email.
     *
     * @return the email
     */
    public String getEmail() {
        return email;
    }

    /**
     * Gets app name.
     *
     * @return the app name
     */
    public String getAppName() {
        return appName;
    }

    /**
     * Gets company.
     *
     * @return the company
     */
    public String getCompany() {
        return company;
    }

    /**
     * Gets sector.
     *
     * @return the sector
     */
    public String getSector() {
        return sector;
    }

    /**
     * Gets website.
     *
     * @return the website
     */
    public String getWebsite() {
        return website;
    }
}
