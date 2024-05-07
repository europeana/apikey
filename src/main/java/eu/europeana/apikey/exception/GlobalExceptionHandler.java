package eu.europeana.apikey.exception;

import eu.europeana.api.commons.error.EuropeanaGlobalExceptionHandler;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import eu.europeana.api.commons.error.EuropeanaApiErrorResponse;

import javax.servlet.http.HttpServletRequest;

/**
 * Global exception handler that catches all errors and logs the interesting ones
 *
 * @author Patrick Ehlert Created on 18 nov 2019 Modified on 4 Feb 2021
 * @author Srishti Singh
 */
@ControllerAdvice
public class GlobalExceptionHandler extends EuropeanaGlobalExceptionHandler {

    /**
     * Handle exception response entity.
     *
     * @param e           the e
     * @param httpRequest the http request
     * @return the response entity
     */
    @ExceptionHandler
    public ResponseEntity<EuropeanaApiErrorResponse> handleException(
            HttpMessageNotReadableException e, HttpServletRequest httpRequest) {
        EuropeanaApiErrorResponse response =
                new EuropeanaApiErrorResponse.Builder(httpRequest, e, stackTraceEnabled())
                        .setStatus(HttpStatus.BAD_REQUEST.value())
                        .setError("Error parsing request body")
                        .setMessage("JSON is either malformed or missing required body")
                        .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST.value())
                .contentType(MediaType.APPLICATION_JSON)
                .body(response);
    }

    /**
     * Handle invalid media type response entity.
     *
     * @param e           the e
     * @param httpRequest the http request
     * @return the response entity
     */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<EuropeanaApiErrorResponse> handleInvalidMediaType(
            HttpMediaTypeNotSupportedException e, HttpServletRequest httpRequest) {

        EuropeanaApiErrorResponse response =
                new EuropeanaApiErrorResponse.Builder(httpRequest, e, stackTraceEnabled())
                        .setStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE.value())
                        .setError(e.getMessage())
                        .setMessage(
                                "Unsupported media type. Supported types are: "
                                        + MediaType.APPLICATION_JSON)
                        .build();

        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE.value())
                .contentType(MediaType.APPLICATION_JSON)
                .body(response);
    }

}
