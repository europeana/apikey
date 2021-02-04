package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when the keycloak user could not be found
 * @author Lúthien
 * Created on 15 okt 2020
 * Modified on 4 Feb 2021
 */
public class MissingKCUserException extends EuropeanaApiException {

    public MissingKCUserException(String userId) {
        super("Error retrieving user information. No keycloak user was found with UserID " + userId);
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }

    @Override
    public HttpStatus getResponseStatus() {
        return HttpStatus.NOT_FOUND;
    }
}
