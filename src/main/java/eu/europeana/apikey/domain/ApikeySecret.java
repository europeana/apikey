package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApikeySecret extends Apikey {
    private String clientSecret;

    public ApikeySecret(String apikey, String firstName, String lastName, String email, String appName, String company, String clientSecret) {
        super(apikey, firstName, lastName, email,appName,company);
        this.clientSecret = clientSecret;
    }

    public String getClientSecret() {
        return clientSecret;
    }
}
