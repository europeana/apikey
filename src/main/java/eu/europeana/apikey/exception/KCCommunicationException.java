package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown  when there problem communication with Keycloak
 * Created by luthien on 15/10/2020.
 * Modified by Srishti Singh on 4 Feb 2021
 */
public class KCCommunicationException extends EuropeanaApiException {

    private int status;

    public KCCommunicationException(String msg, int status) {
        super(msg);
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