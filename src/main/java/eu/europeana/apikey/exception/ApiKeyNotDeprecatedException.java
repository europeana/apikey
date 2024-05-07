package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when trying to enable an API key that was not disabled/deprecated
 *
 * @author Patrick Ehlert Created on 18 nov 2019 Modified on 4 Feb 2021
 */
public class ApiKeyNotDeprecatedException extends EuropeanaApiException {

    /**
     * Instantiates a new Api key not deprecated exception.
     *
     * @param id the id
     */
    public ApiKeyNotDeprecatedException(String id) {
        super("API key " + id + " is not deprecated!");
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }

    @Override
    public HttpStatus getResponseStatus() {
        return HttpStatus.BAD_REQUEST;
    }
}
