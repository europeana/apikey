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

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * Created by luthien on 4/12/2017.
 */

@JsonInclude(NON_EMPTY)
public class ApikeyUpdate {

    private String apikey;
    private String website;
    private String appName;
    private String company;
    private String sector;
    private String email;
    private String firstName;
    private String lastName;

    public String getApikey() {
        return apikey;
    }

    public String getWebsite() {
        return website;
    }

    public String getAppName() {
        return appName;
    }

    public String getCompany() {
        return company;
    }

    public String getSector() {
        return sector;
    }

    public String getEmail() {
        return email;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }
}
