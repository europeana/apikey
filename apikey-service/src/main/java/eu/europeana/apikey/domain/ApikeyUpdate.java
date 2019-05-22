package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * Created by luthien on 4/12/2017.
 */

@JsonInclude(NON_EMPTY)
public class ApikeyUpdate implements ApikeyAction {

    public ApikeyUpdate(String apikey,
                        String firstName,
                        String lastName,
                        String email,
                        String appName,
                        String company,
                        String sector,
                        String website) {
        this.apikey  = apikey;
        this.firstName  = firstName;
        this.lastName   = lastName;
        this.email      = email;
        this.appName    = appName;
        this.company    = company;
        this.sector     = sector;
        this.website    = website;
    }

    //empty constructor needed to facilitate integration testing
    public ApikeyUpdate() {}

    private String apikey;
    private String firstName;
    private String lastName;
    private String email;
    private String appName;
    private String company;
    private String sector;
    private String website;

    public String getApikey() {
        return apikey;
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
