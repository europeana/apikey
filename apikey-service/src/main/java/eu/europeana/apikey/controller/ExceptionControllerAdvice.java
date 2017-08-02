/*
 * Copyright 2007-2017 The Europeana Foundation
 *
 *  Licenced under the EUPL, Version 1.1 (the "Licence") and subsequent versions as approved
 *  by the European Commission;
 *  You may not use this work except in compliance with the Licence.
 *
 *  You may obtain a copy of the Licence at:
 *  http://joinup.ec.europa.eu/software/page/eupl
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under
 *  the Licence is distributed on an "AS IS" basis, without warranties or conditions of
 *  any kind, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under
 *  the Licence.
 */

package eu.europeana.apikey.controller;

import eu.europeana.apikey.domain.ApiKey;
import eu.europeana.apikey.domain.ApiKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletRequest;

/**
 * This class functions as a global catch to tame wild uncouth exceptions with and learn them some manners
 * Created by luthien on 01/08/2017.
 */
@RestControllerAdvice
public class ExceptionControllerAdvice {

    private static final int STATUS_406 = 406;
    private static final String ERROR_406 = "unacceptable request header";
    private static final String MESSAGE_406 = "header 'Accept' must be 'application/json";

//    @ExceptionHandler(value = {HttpMediaTypeNotAcceptableException.class})
//    @ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
//    public ModelAndView handleMediaTypeNotAcceptable(HttpServletRequest req, HttpMediaTypeNotAcceptableException ex){
//        ObjectMapper mapper = new ObjectMapper();
//        ApiKeyException apiKeyException = new ApiKeyException(STATUS_406, ERROR_406, MESSAGE_406);
//        Map<String, Object> model = new LinkedHashMap<>();
//        try {
//            String jsonInString = mapper.writeValueAsString(apiKeyException);
//            model.put("json", jsonInString);
//        } catch (JsonProcessingException e) {
//            model.put("status", String.valueOf(STATUS_406));
//            model.put("error", ERROR_406);
//            model.put("message", MESSAGE_406);
//        }
//        return new ModelAndView("json", model);
//    }

//    @ExceptionHandler(value = {HttpMediaTypeNotAcceptableException.class})
//    @ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
//    public ResponseEntity<Object> handleMediaTypeNotAcceptable(HttpServletRequest req, HttpMediaTypeNotAcceptableException ex){
//        return new ResponseEntity<Object>(
//                new ApiKeyException(406, "unacceptable request header", "header 'Accept' must be 'application/json"), HttpStatus.BAD_REQUEST);
//    }

    @ExceptionHandler(value = {HttpMediaTypeNotAcceptableException.class})
    @ResponseStatus(HttpStatus.NOT_ACCEPTABLE)
    public ResponseEntity<ApiKey> handleMediaTypeNotAcceptable(HttpServletRequest req, HttpMediaTypeNotAcceptableException ex){
        return new ResponseEntity<>(
                new ApiKey("1", "baikalmeer", "6", "244", "wepst", "gnap"), HttpStatus.NOT_ACCEPTABLE);
    }

}
