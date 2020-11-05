package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when we try to recreate a keycloak client for an apikey that already has a keycloakId set
 * @author Patrick Ehlert
 * Created on 21 jan 2020
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class KCIdNotEmptyException extends ApiKeyException {

    public KCIdNotEmptyException(String apiKey, String keycloakId) {
        super("ApiKey " + apiKey + " already has a keycloak client id set (" + keycloakId + ")");
    }

    public KCIdNotEmptyException(String apiKey, String keycloakId, String action) {
        super("Encountered a problem preparing to " + action + " Apikey: " + apiKey + ". There exists " +
              "an associated Keycloak client (id: " + keycloakId + ", clientId: " + apiKey +
              "). Please use the combined apikey + client " + " " + action + " endpoint instead.");
    }



    @Override
    public boolean doLogStacktrace() {
        return false;
    }
}
