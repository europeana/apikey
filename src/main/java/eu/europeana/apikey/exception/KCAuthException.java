package eu.europeana.apikey.exception;

/**
 * Created by luthien on 15/10/2020.
 */
public class KCAuthException extends KCComException {

    private String cause;


    public KCAuthException(String error, String cause) {
        super(error);
        this.cause = cause;
    }

    public String getErrorAndCause() {
        return "Error: " + super.getError() + "; cause: " + cause;
    }

}
