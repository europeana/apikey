package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when there is not enough information, e.g. to create a new API key
 *
 * @author Patrick Ehlert Created on 18 nov 2019 Modified on 4 Feb 2021
 */
public class MissingDataException extends EuropeanaApiException {

    /**
     * Instantiates a new Missing data exception.
     *
     * @param msg the msg
     */
    public MissingDataException(String msg) {
        super(msg);
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
