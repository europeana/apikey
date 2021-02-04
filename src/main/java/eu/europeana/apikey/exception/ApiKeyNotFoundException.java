package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when there the requested API key cannot be found
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 * Modified on 4 Feb 2021
 */
public class ApiKeyNotFoundException extends EuropeanaApiException {

    public ApiKeyNotFoundException(String id) {
        super("API key " + id + " does not exist.");
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }

    @Override
    public HttpStatus getResponseStatus() {
        return HttpStatus.NOT_FOUND;
    }
}
