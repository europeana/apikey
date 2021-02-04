package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaApiException;
import org.springframework.http.HttpStatus;

/**
 * Created by luthien on 15/10/2020.
 * Modified by Srishti Singh on 4 Feb 2021
 */
public class KCAuthException extends EuropeanaApiException {

    private String error;
    private String cause;

    public KCAuthException(String error, String cause) {
        super("Error : " + error + "; cause : " + cause);
        this.error = error;
        this.cause = cause;
    }

    public String getErrorAndCause() {
        return "Error: " + error+ "; cause: " + cause;
    }

    @Override
    public HttpStatus getResponseStatus() {
        return HttpStatus.UNAUTHORIZED;
    }

}
