package eu.europeana.apikey.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when an email cannot be sent (e.g. confirmation email after creating an apikey)
 * @author Maike
 * Created on 20 nov 2019
 */
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class SendMailException extends ApiKeyException {

    public SendMailException(String message, Throwable t) {
        super(message, t);
    }
}
