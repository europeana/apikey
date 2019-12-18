package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when trying to create a new API key for an application name and email address that is already in use
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class ApikeyExistsException extends ApikeyException {

    public ApikeyExistsException(String email, String appName) {
        super("Key already exists", "There already is an API key registered with application name " + appName + " and email " + email+ ".");
    }

    public boolean doLogStacktrace() {
        return false;
    }
}
