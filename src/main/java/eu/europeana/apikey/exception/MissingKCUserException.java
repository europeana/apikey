package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when the keycloak user could not be found
 * @author Lúthien
 * Created on 15 okt 2020
 */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class MissingKCUserException extends ApiKeyException {

    public MissingKCUserException(String userId) {
        super("Error retrieving user information", "No keycloak user was found with UserID " + userId);
    }

    @Override
    public boolean doLogStacktrace() {
        return false;
    }
}
