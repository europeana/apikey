package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when we try to create a keycloak client that already exists
 *
 * @author Patrick Ehlert Created on 21 jan 2020 Modified on 4 Feb 2021
 */
public class KCClientExistsException extends EuropeanaApiException {

    /**
     * Instantiates a new Kc client exists exception.
     *
     * @param kcClientId the kc client id
     */
    public KCClientExistsException(String kcClientId) {
        super("There already is a keycloak client with id " + kcClientId);
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
