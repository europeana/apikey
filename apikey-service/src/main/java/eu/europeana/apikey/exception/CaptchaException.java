package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when the captcha could not be validated
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class CaptchaException extends ApiKeyException {

    public CaptchaException(String message) {
        super("Error validating captcha", message);
    }

}
