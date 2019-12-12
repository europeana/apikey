package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when no API key was specified (in a validate request)
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class MissingKeyException extends ApiKeyException {

    public MissingKeyException(String details) {
        super("No API key in header", details);
    }

    public boolean doLogStacktrace() {
        return false;
    }
}
