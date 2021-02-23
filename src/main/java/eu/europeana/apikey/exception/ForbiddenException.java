package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when there is not enough information, e.g. to create a new API key
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 * Modified on 4 Feb 2021
 */
public class ForbiddenException extends EuropeanaApiException {

    public ForbiddenException() {
        super("Operation is not allowed by this user");
    }

    public ForbiddenException(String actionName) {
        super("Operation " + actionName + " is not allowed by this user");
    }

    public ForbiddenException(String error, String message) {
        super(error, message);
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }

    @Override
    public HttpStatus getResponseStatus() {
        return HttpStatus.FORBIDDEN;
    }
}
