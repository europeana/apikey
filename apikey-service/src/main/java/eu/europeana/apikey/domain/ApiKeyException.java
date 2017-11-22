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

package eu.europeana.apikey.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;

/**
 * Created by luthien on 01/08/2017.
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiKeyException {
    private static final long serialVersionUID = 43L;

    @JsonView(View.Public.class)
    @JsonProperty("timestamp")
    private Long timestamp = System.currentTimeMillis() / 1000L;

    @JsonView(View.Public.class)
    @JsonProperty("status")
    private int status;

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
        this.additionalInfo = ex.getMessage();
    }

    public ApiKeyException(int status) {
        this.status = status;
    }

    public ApiKeyException(int status, String error) {
        this(status);
        this.error = error;
    }

    public ApiKeyException(int status, String error, String message) {
        this(status, error);
        this.message = message;
    }

    public ApiKeyException(int status, String error, String message, String additionalInfo) {
        this(status, error, message);
        this.additionalInfo = additionalInfo;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getAdditionalInfo() {
        return additionalInfo;
    }

    public void setAdditionalInfo(String additionalInfo) {
        this.additionalInfo = additionalInfo;
    }


}
