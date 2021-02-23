package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when no API key was specified (in a validate request)
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
public class MissingKeyException extends EuropeanaApiException {

    public MissingKeyException(String details) {
        super("No API key in header. " + details);
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
