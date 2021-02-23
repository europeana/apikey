package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when trying to perform an action on a deprecated API key
 */
public class ApiKeyDeprecatedException extends EuropeanaApiException {

    public ApiKeyDeprecatedException(String id) {
        super("The API key " + id + " is deprecated!");
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }

    @Override
    public HttpStatus getResponseStatus() {
        return HttpStatus.GONE;
    }
}
