package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when trying to create a new API key for an application name and email address that is already in use
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
public class ApiKeyExistsException extends EuropeanaApiException {

    public ApiKeyExistsException(String email, String appName) {
        super("There already is an API key registered with application name " + appName + " and email " + email+ ".");
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
