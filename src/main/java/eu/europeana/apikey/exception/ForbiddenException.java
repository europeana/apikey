package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when there is not enough information, e.g. to create a new API key
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class ForbiddenException extends ApiKeyException {

    public ForbiddenException() {
        super("Forbidden", "Operation is not allowed by this user");
    }

    public boolean doLogStacktrace() {
        return false;
    }
}
