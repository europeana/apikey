package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class FullApikey extends Apikey {
    private String clientSecret;

    public FullApikey(String apikey, String firstName, String lastName, String email, String appName, String clientSecret) {
        super(apikey, firstName, lastName, email,appName);
        this.clientSecret = clientSecret;
    }

    public String getClientSecret() {
        return clientSecret;
    }
}
