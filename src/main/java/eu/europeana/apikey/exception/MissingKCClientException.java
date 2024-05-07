package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when the keycloak client could not be found
 *
 * @author Patrick Ehlert Created on 18 nov 2019 Mofified on 4 Feb 2021
 */
public class MissingKCClientException extends EuropeanaApiException {

    /**
     * Instantiates a new Missing kc client exception.
     *
     * @param apiKey the api key
     */
    public MissingKCClientException(String apiKey) {
        super("Error retrieving client information. No keycloak client was found for API key " + apiKey);
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }

    @Override
    public HttpStatus getResponseStatus() {
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
