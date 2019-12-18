package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when trying to enable an API key that was not disabled/deprecated
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class ApikeyNotDeprecatedException extends ApikeyException {

    public ApikeyNotDeprecatedException(String id) {
        super("Bad request", "API key " + id + " is not deprecated!");
    }

    public boolean doLogStacktrace() {
        return false;
    }
}
