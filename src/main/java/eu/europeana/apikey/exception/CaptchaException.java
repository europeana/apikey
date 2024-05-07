package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when the captcha could not be validated
 *
 * @author Patrick Ehlert Created on 18 nov 2019 Modified on 4 Feb 2021
 */
public class CaptchaException extends EuropeanaApiException {

    /**
     * Instantiates a new Captcha exception.
     *
     * @param message the message
     */
    public CaptchaException(String message) {
        super("Error validating captcha " + message);
    }

    @Override
    public HttpStatus getResponseStatus() {
        return HttpStatus.UNAUTHORIZED;
    }
}
