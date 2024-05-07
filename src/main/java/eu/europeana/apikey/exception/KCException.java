package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when there are problems communicating with Keycloak
 */
public class KCException extends EuropeanaApiException {

    private int status;

    /**
     * Instantiates a new Kc exception.
     *
     * @param msg    the msg
     * @param status the status
     */
    public KCException(String msg, int status) {
        super(msg);
        this.status = status;
    }

    /**
     * Instantiates a new Kc exception.
     *
     * @param msg    the msg
     * @param status the status
     * @param t      the t
     */
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

    /**
     * Gets status.
     *
     * @return the status
     */
    public int getStatus() {
        return status;
    }
}
