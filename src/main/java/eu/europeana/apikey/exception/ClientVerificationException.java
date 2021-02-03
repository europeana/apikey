package eu.europeana.apikey.exception;

import org.apache.http.annotation.Contract;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when the keycloak client verification failed (e.g. because of a mismatching client secret)
 * @author Luthien
 * Created on 28 jan 2021
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class ClientVerificationException extends ApiKeyException {

    public ClientVerificationException(String apiKey) {
        super("Error retrieving client information", "No keycloak client was found for API key " + apiKey);
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }
}
