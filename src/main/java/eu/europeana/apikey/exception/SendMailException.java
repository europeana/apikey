package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Exception thrown when an email cannot be sent (e.g. confirmation email after creating an apikey)
 * @author Maike
 * Created on 20 nov 2019
 * Modified on 4 Feb 2021
 */
public class SendMailException extends EuropeanaApiException {

    public SendMailException(String message, Throwable t) {
        super(message, t);
    }

    @Override
    public HttpStatus getResponseStatus() {
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
