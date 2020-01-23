package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when we try to create a keycloak client that already exists
 * @author Patrick Ehlert
 * Created on 21 jan 2020
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class KCClientExistsException extends ApiKeyException {

    public KCClientExistsException(String kcClientId) {
        super("There already is a keycloak client with id " + kcClientId);
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }
}
