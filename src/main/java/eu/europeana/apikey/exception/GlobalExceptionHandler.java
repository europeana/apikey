package eu.europeana.apikey.exception;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletResponse;

/**
 * Global exception handler that catches all errors and logs the interesting ones
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOG = LogManager.getLogger(GlobalExceptionHandler.class);

    /**
     * Checks if we should log an error (and its stacktrace) and rethrows it
     * @param e caught exception
     * @throws ApiKeyException rethrown exception
     */
    @ExceptionHandler(ApiKeyException.class)
    public void handleApiKeyException(HttpServletResponse response, ApiKeyException e) throws ApiKeyException {
        if (e.doLog()) {
            if (e.doLogStacktrace()) {
                LOG.error("Caught exception", e);
            } else {
                LOG.error("Caught exception: " + e.getMessage());
            }
        }

        // We simply rethrow so Spring & Jackson will automatically return a json error. Note that this requires all exceptions
        // to have a ResponseStatus annotation, otherwise the exception will default to 500 status
        throw e;
    }
}
