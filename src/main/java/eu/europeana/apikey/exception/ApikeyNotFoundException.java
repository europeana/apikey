package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when there the requested API key cannot be found
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class ApikeyNotFoundException extends ApikeyException {

    public ApikeyNotFoundException(String id) {
        super("Not found", "API key " + id + " does not exist.");
    }

    public boolean doLogStacktrace() {
        return false;
    }
}
