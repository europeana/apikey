package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when there is not enough information, e.g. to create a new API key
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class MissingDataException extends ApiKeyException {

    public MissingDataException(String error, String details) {
        super(error, details);
    }

    public boolean doLogStacktrace() {
        return false;
    }
}
