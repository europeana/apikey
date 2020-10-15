package eu.europeana.apikey.exception;

/**
 * Created by luthien on 15/10/2020.
 */
public class KCComException extends Exception {


    private int status;

    private String error;

    private String message;

    private String additionalInfo;


    public KCComException(Throwable ex) {
        super.initCause(ex);
    }

    public KCComException(String message) {
        this.message = message;
    }

    public KCComException(String error, String message) {
        this.error = error;
        this.message = message;
    }
    public KCComException(String error, String message, int status) {
        this.error = error;
        this.message = message;
        this.status = status;
    }

    public KCComException(String message, Throwable ex) {
        super.initCause(ex);
        this.message = message;
    }

    public int getStatus() {
        return status;
    }

    public String getError() {
        return error;
    }

    @Override
    public String getMessage() {
        return message;
    }

}
