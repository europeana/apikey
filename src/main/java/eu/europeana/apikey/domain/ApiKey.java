package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.*;
import org.springframework.format.annotation.DateTimeFormat;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Date;

import static eu.europeana.apikey.util.Tools.nvl;

/**
 * API key as it is used internally and stored in the database
 * Created by luthien on 18/04/2017.
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@Entity
@Table(name = "apikey")
public class ApiKey {

    /**
     * the api key
     */
    @Id
    @Column(name = "apikey")
    @JsonProperty("apiKey")
    @JsonView(View.Public.class)
    private String apiKey;

    /**
     * the UUID of the Keycloak client if that is generated for this key
     */
    @Column(name = "keycloakid")
    @JsonProperty("keycloakId")
    @JsonView(View.Public.class)
    private String keycloakId;

    /**
     * auto-filled creation timestamp
     */
    @NotNull
    @Column(name = "registrationdate")
    @JsonProperty("registrationDate")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
    @JsonView(View.Public.class)
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss'Z'")
    private Date registrationDate;

    /**
     * Website of the application or user
     */
    @Size(max = 100)
    @Column(name = "website")
    @JsonProperty("website")
    @JsonView(View.Public.class)
    private String website;

    /**
     * auto-filled, timestamp of activation
     */
    @Column(name = "activationdate")
    @JsonProperty("activationDate")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss'Z'")
    @JsonView(View.Public.class)
    private Date activationDate;

    /**
     * Name of the application using this key
     */
    @NotNull
    @Size(max = 255)
    @Column(name = "appname")
    @JsonProperty("appName")
    @JsonView(View.Public.class)
    private String appName;

    /**
     * Company or institute name
     */
    @NotNull
    @Size(max = 100)
    @Column(name = "company")
    @JsonProperty("company")
    @JsonView(View.Public.class)
    private String company;

    /**
     * Sector of institute / company
     */
    @Size(max = 255)
    @Column(name = "sector")
    @JsonProperty("sector")
    @JsonView(View.Public.class)
    private String sector;

    /**
     * Email address
     */
    @NotNull
    @Size(max = 100)
    @Column(name = "email")
    @JsonProperty("email")
    @JsonView(View.Public.class)
    protected String email;

    /**
     * First name of user
     */
    @NotNull
    @Size(max = 100)
    @Column(name = "firstname")
    @JsonProperty("firstName")
    @JsonView(View.Public.class)
    private String firstName;

    /**
     * last name of user
     */
    @NotNull
    @Size(max = 100)
    @Column(name = "lastname")
    @JsonProperty("lastName")
    @JsonView(View.Public.class)
    private String lastName;

    /**
     * timestamp when this key was disabled
     */
    @Column(name = "deprecationdate")
    @JsonProperty("deprecationDate")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss'Z'")
    @JsonView(View.Public.class)
    private Date deprecationDate;

    /**
     * timestamp set to the moment the key was last validated
     */
    @Column(name = "lastaccessdate")
    @JsonProperty("lastAccessDate")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss'Z'")
    @JsonView(View.Public.class)
    private Date lastAccessDate;

    /**
     * free text field
     */
    @Size(max = 255)
    @Column(name = "comments")
    @JsonProperty("comments")
    @JsonView(View.Public.class)
    private String comments;

    /**
     * constructor
     */
    public ApiKey() {
        // default constructor required by JPA/Hibernate for deserialization
    }

    /**
     * Constructor with all required fields. Note that there can be old API keys stored in the database that do not have
     * an appName or company
     *
     * @param apiKey Apikey string
     * @param firstName  User's first name
     * @param lastName  User's second name
     * @param email User's email address
     * @param appName Name of application the key is intended for
     * @param company Name of institute or company
     */
    public ApiKey(String apiKey, String firstName, String lastName, String email, String appName, String company) {
        this.apiKey           = apiKey;
        this.keycloakId       = null;
        this.firstName        = firstName;
        this.lastName         = lastName;
        this.email            = email;
        this.appName          = appName;
        this.company          = company;
        this.registrationDate = new Date();
    }


    /**
     * Constructor with all fields
     * @param copy Apikey to copy fields from
     */
    public ApiKey(ApiKey copy) {
        this.apiKey           = copy.apiKey;
        this.keycloakId       = copy.keycloakId;
        this.registrationDate = copy.registrationDate;
        this.website          = copy.website;
        this.activationDate   = copy.activationDate;
        this.appName          = copy.appName;
        this.company          = copy.company;
        this.sector           = copy.sector;
        this.email            = copy.email;
        this.firstName        = copy.firstName;
        this.lastName         = copy.lastName;
        this.deprecationDate  = copy.deprecationDate;
        this.lastAccessDate   = copy.lastAccessDate;
        this.comments         = copy.comments;
    }

    /**
     *
     * @return the apikey string
     */
    public String getApiKey() {
        return apiKey;
    }

    /**
     *
     * @param apiKey sets the apikey string
     */
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    /**
     * For combined api keys / keycloak clients only
     * @return the UUID linking to the associated Keycloak Client (when created)
     */
    @JsonIgnore
    public String getKeycloakId() {
        return keycloakId;
    }

    /**
     * For combined api keys / keycloak clients only
     * @param keycloakId sets UUID linking to the associated Keycloak Client (when created)
     */
    public void setKeycloakId(String keycloakId) {
        this.keycloakId = keycloakId;
    }

    /**
     *
     * @return timestamp of registration this key
     */
    public Date getRegistrationDate() {
        return registrationDate;
    }

    /**
     *
     * @param registrationDate sets registration timestamp
     */
    public void setRegistrationDate(Date registrationDate) {
        this.registrationDate = registrationDate;
    }

    /**
     *
     * @return string containing name or URL to website associated with this API Key
     */
    public String getWebsite() {
        return website;
    }

    /**
     *
     * @param website sets name or URL to website associated with this API Key.
     */
    public void setWebsite(String website) {
        this.website = website;
    }

    /**
     *
     * @return timestamp op activating this API key
     */
    public Date getActivationDate() {
        return activationDate;
    }

    /**
     *
     * @param activationDate sets activation timestamp for this API key
     */
    public void setActivationDate(Date activationDate) {
        this.activationDate = activationDate;
    }

    /**
     *
     * @return returns string containing app name
     */
    public String getAppName() {
        return appName;
    }

    /**
     *
     * @param appName sets the associated application name
     */
    public void setAppName(String appName) {
        this.appName = appName;
    }

    /**
     *
     * @return string containing institute or company name
     */
    public String getCompany() {
        return company;
    }

    /**
     *
     * @param company sets institute or company name
     */
    public void setCompany(String company) {
        this.company = company;
    }

    /**
     *
     * @return string containing the name of the sector of the institute or company
     */
    public String getSector() {
        return sector;
    }

    /**
     *
     * @param sector returns the name of the sector of the institute or company
     */
    public void setSector(String sector) {
        this.sector = sector;
    }

    /**
     *
     * @return the email address associated wih this key
     */
    public String getEmail() {
        return email;
    }

    /**
     *
     * @param email sets the associated email address
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     *
     * @return the user's first name
     */
    public String getFirstName() {
        return firstName;
    }

    /**
     *
     * @param firstName sets the user's first name
     */
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    /**
     *
     * @return last name of the user
     */
    public String getLastName() {
        return lastName;
    }

    /**
     *
     * @param lastName sets the user's last name
     */
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    /**
     *
     * @return returns disabled timestamp of this key
     */
    public Date getDeprecationDate() {
        return deprecationDate;
    }

    /**
     *
     * @param deprecationDate sets disabled timestamp of this key
     */
    public void setDeprecationDate(Date deprecationDate) {
        this.deprecationDate = deprecationDate;
    }

    /**
     *
     * @return last validation timestamp
     */
    public Date getLastAccessDate() {
        return lastAccessDate;
    }

    /**
     *
     * @param lastAccessDate sets latest validation timestamp
     */
    public void setLastAccessDate(Date lastAccessDate) {
        this.lastAccessDate = lastAccessDate;
    }

    /**
     *
     * @return comment string
     */
    public String getComments() {
        return comments;
    }

    /**
     *
     * @param comments sets comment string
     */
    public void setComments(String comments) {
        this.comments = comments;
    }

    /**
     *
     * @return to-string version of object
     */
    @Override
    public String toString() {
        return "ApiKey {" +
                " apikey = " + apiKey +
                ", keycloakId = " + keycloakId +
                ", firstName = " + nvl(firstName) +
                ", lastName = " + nvl(lastName) +
                ", email = " + nvl(email) +
                ", appName = " + nvl(appName) +
                ", website = " + nvl(website) +
                ", company = " + nvl(company) +
                ", sector = " + nvl(sector) +
                ", activationDate = " + nvl(activationDate) +
                ", registrationDate = " + nvl(registrationDate) +
                ", lastAccessDate = " + nvl(lastAccessDate) +
                ", deprecationDate = " + nvl(deprecationDate) +
                " }";
    }
}
