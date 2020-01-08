package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * ApiKey and Secret. Only when registering is this returned once to the user. After that the secret is not sent again
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiKeySecret extends ApiKey {
    private String clientSecret;

    public ApiKeySecret(String apiKey,
                        String firstName,
                        String lastName,
                        String email,
                        String appName,
                        String company,
                        String clientSecret) {
        super(apiKey, firstName, lastName, email, appName, company);
        this.clientSecret = clientSecret;
    }

    public String getClientSecret() {
        return clientSecret;
    }
}
