package eu.europeana.apikey.exception;

import eu.europeana.apikey.domain.ErrorResponse;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;

/**
 * Global exception handler that catches all errors and logs the interesting ones
 * @author Patrick Ehlert
 * Created on 18 nov 2019
 */
@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler
 {

    private static final Logger LOG = LogManager.getLogger(GlobalExceptionHandler.class);
    private static final String MISSING_PARAMETER    = " Required parameter(s): ";
    private static final String BAD_REQUEST          = "Bad Request";
    private static final String BAD_EMAIL_FORMAT    = " Email is not properly formatted. ";
    private static final String EMAIL_FORMAT_ERROR    = "emailNotValid";


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
                LOG.error("Caught exception: {}", e.getMessage());
            }
        }

        // We simply rethrow so Spring & Jackson will automatically return a json error. Note that this requires all exceptions
        // to have a ResponseStatus annotation, otherwise the exception will default to 500 status
        throw e;
    }

     /**
      * handles MethodArgumentNotValidException
      * @param ex caught exception
      * @return ErrorResponse
      */
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        ArrayList<String> missingList = new ArrayList<>();
        String message = new String() ;
        for(ObjectError error : ex.getBindingResult().getAllErrors()) {
            if(StringUtils.equalsIgnoreCase(error.getDefaultMessage(), EMAIL_FORMAT_ERROR)) {
                message = BAD_EMAIL_FORMAT;
            } else {
                missingList.add(error.getDefaultMessage());
            }
        }
        if(!missingList.isEmpty()) {
            message = message + MISSING_PARAMETER  + missingList + " not provided";
        }
        String path = StringUtils.substringAfter(request.getDescription(false), "uri=");
        ErrorResponse error = new ErrorResponse(System.currentTimeMillis(),
                                                HttpStatus.BAD_REQUEST.value(),
                                                BAD_REQUEST,
                                                message,
                                                path);
        LOG.error("Caught exception {} ", message);
        return new ResponseEntity(error, HttpStatus.BAD_REQUEST);
    }

}
