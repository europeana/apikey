package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

@JsonInclude(NON_EMPTY)
public class ApikeyDetails implements ApikeyAction {
    private String firstName;
    private String lastName;
    private String email;
    private String appName;
    private String company;
    private String sector;
    private String website;

    //empty constructor needed to facilitate integration testing
    public ApikeyDetails(){}

    public ApikeyDetails(String firstName, String lastName, String email){
        this.firstName  = firstName;
        this.lastName   = lastName;
        this.email      = email;
    }

    public ApikeyDetails(String firstName,
                        String lastName,
                        String email,
                        String appName,
                        String company,
                        String sector,
                        String website) {
        this(firstName, lastName, email);
        this.appName    = appName;
        this.company    = company;
        this.sector     = sector;
        this.website    = website;
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
