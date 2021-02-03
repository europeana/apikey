package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when the keycloak client access token could not be retrieved
 * @author Luthien
 * Created on 28 jan 2021
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class ClientTokenRetrievalException extends ApiKeyException {

    public ClientTokenRetrievalException(String message, Throwable ex) {
        super(message, ex);
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }
}
