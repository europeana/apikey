package eu.europeana.apikey.exception;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;
import eu.europeana.apikey.domain.View;

import java.util.Date;


/**
 * Created by luthien on 01/08/2017.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiKeyException extends Exception {

    @JsonView(View.Public.class)
    @JsonProperty("timestamp")
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss'Z'")
    private final Date timestamp = new Date();

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


    public ApiKeyException(Throwable ex) {
        super.initCause(ex);
    }

    public ApiKeyException(String message) {
        this.message = message;
    }

    public ApiKeyException(String error, String message) {
        this.error = error;
        this.message = message;
    }

    public ApiKeyException(String message, Throwable ex) {
        super.initCause(ex);
        this.message = message;
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

    public Date getTimestamp() {
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
