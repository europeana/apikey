package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when there problem communicating with Keycloak
 */
public class KCException extends EuropeanaApiException {

    private int status;

    public KCException(String msg, int status) {
        super(msg);
        this.status = status;
    }

    public KCException(String msg, int status, Throwable t) {
        super(msg, t);
        this.status = status;
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }

    @Override
    public HttpStatus getResponseStatus() {
        return HttpStatus.valueOf(status);
    }

    public int getStatus() {
        return status;
    }
}
