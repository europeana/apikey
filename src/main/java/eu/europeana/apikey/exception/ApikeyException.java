package eu.europeana.apikey.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;
import eu.europeana.apikey.domain.View;


/**
 * Created by luthien on 01/08/2017.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApikeyException extends Exception {

    @JsonView(View.Public.class)
    @JsonProperty("timestamp")
    private Long timestamp = System.currentTimeMillis() / 1000L;

    @JsonView(View.Public.class)
    @JsonProperty("status")
    private Integer status;

    @JsonView(View.Public.class)
    @JsonProperty("error")
    private String error;

    @JsonView(View.Public.class)
    @JsonProperty("message")
    private String message;

    @JsonView(View.Public.class)
    @JsonProperty("additionalInfo")
    private String additionalInfo;


    public ApikeyException(Throwable ex) {
        this.initCause(ex);
    }

    public ApikeyException(String error) {
        this.error = error;
    }

    public ApikeyException(String error, String message) {
        this(error);
        this.message = message;
    }

    public ApikeyException(String message, Throwable ex) {
        this.message = message;
        this.initCause(ex);
    }

    /**
     * @return boolean indicating whether this type of exception should be logged or not
     */
    public boolean doLog() {
        return true; // default we log all exceptions
    }

    /**
     * @return boolean indicating whether the stacktrace of the exception should be logged or not (only works when
     * doLog returns true)
     */
    public boolean doLogStacktrace() {
        return true; // default we log all stacktraces
    }

    public Long getTimestamp() {
        return timestamp;
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
