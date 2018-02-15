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


/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey.controller;

import com.fasterxml.jackson.annotation.JsonView;
import eu.europeana.apikey.domain.*;
import eu.europeana.apikey.mail.MailServiceImpl;
import eu.europeana.apikey.repos.ApikeyRepo;
import eu.europeana.apikey.util.ApiName;
import eu.europeana.apikey.util.PassGenerator;
import eu.europeana.apikey.util.Tools;
import org.apache.commons.lang.math.RandomUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Date;

@RestController
@RequestMapping("/apikey")
public class ApikeyController {

    private final ApikeyRepo apikeyRepo;
    private static final String READ  = "read";
    private static final String WRITE = "write";
    private static final Logger LOG   = LogManager.getLogger(ApikeyController.class);

    @Autowired
    public ApikeyController(ApikeyRepo apikeyRepo) {
        this.apikeyRepo = apikeyRepo;
    }

    @Autowired
    public MailServiceImpl emailService;


    @Autowired
    public SimpleMailMessage apikeyCreatedMail;

    /**
     * Generates a new Apikey with the following mandatory values supplied in a JSON request body:
     * - firstName
     * - lastName
     * - email
     * - level (either 'default' or 'admin')
     *
     * The following fields are optional:
     * - website
     * - company
     * - appName
     * - sector
     *
     * The Apikey and Privatekey fields are generated: Apikey is a unique and random 'readable' lowercase string,
     * 8 to 12 characters long, e.g. 'rhossindri', 'viancones' or 'ebobrent'. Privatekey is a regular random string
     * mix of upper- and lowercase characters and numbers, eg. 'mh8Hvi6uXR' or 'Kts8H5ResV'.
     *
     * Upon successful execution, the code will send an email message containing the Apikey and Privatekey to the
     * email address supplied in the request.
     *
     * @param   apikeyCreate requestbody containing supplied values
     *
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in apikey.java
     *          HTTP 201 upon successful Apikey creation
     *          HTTP 400 when a required parameter is missing or (for 'Level') has an invalid value
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 406 if a response MIME type other than application/JSON was requested
     *          HTTP 415 if the submitted request does not contain a valid JSON body
     */
//    @JsonView(View.Public.class) -- commented out for EA-725
    @CrossOrigin(maxAge = 600)
    @RequestMapping(method = RequestMethod.POST,
                    produces = MediaType.APPLICATION_JSON_VALUE,
                    consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> save(@RequestBody ApikeyCreate apikeyCreate) {
        LOG.debug("creating new apikey");
        String missing = mandatoryMissing(apikeyCreate);
        if (!missing.equals("")){
            LOG.debug(missing + ", abort creating apikey");
            return new ResponseEntity<>(new ApikeyException(400, "missing parameter", missing), HttpStatus.BAD_REQUEST);
        }

        PassGenerator pg = new PassGenerator();
        String        newApiKey;
        do {
            newApiKey = pg.generate(RandomUtils.nextInt(4) + 8);
        } while (null != this.apikeyRepo.findOne(newApiKey));

        Apikey apikey = new Apikey(newApiKey,
                                   Tools.generatePassPhrase(10),
                                   apikeyCreate.getFirstName(),
                                   apikeyCreate.getLastName(),
                                   apikeyCreate.getEmail(),
                                   null != apikeyCreate.getLevel() && apikeyCreate.getLevel()
                                            .equalsIgnoreCase(Level.ADMIN.getLevelName()) ?
                                            Level.ADMIN.getLevelName() : Level.CLIENT.getLevelName());
        if (null != apikeyCreate.getWebsite()) {
            apikey.setWebsite(apikeyCreate.getWebsite());
        }
        if (null != apikeyCreate.getAppName()) {
            apikey.setAppName(apikeyCreate.getAppName());
        }
        if (null != apikeyCreate.getCompany()) {
            apikey.setCompany(apikeyCreate.getCompany());
        }
        if (null != apikeyCreate.getSector()) {
            apikey.setSector(apikeyCreate.getSector());
        }
        this.apikeyRepo.save(apikey);
        LOG.debug("apikey: {} created", apikey.getApikey());

        emailService.sendSimpleMessageUsingTemplate(apikey.getEmail(),
                                                    "Your Europeana API keys",
                                                    apikeyCreatedMail,
                                                    apikey.getFirstName(),
                                                    apikey.getLastName(),
                                                    apikey.getApikey(),
                                                    apikey.getPrivatekey());
        return new ResponseEntity<>(apikey, HttpStatus.CREATED);
    }

    /**
     * Changes the registration details of an existing API key for the following public and non-generated values,
     * if they are supplied in the JSON request body:
     *
     * - firstName
     * - lastName
     * - email
     * - company
     * - appName
     * - sector
     *
     * @param   apikeyUpdate RequestBody containing supplied values
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in apikey.java
     *          HTTP 200 upon successful Apikey update
     *          HTTP 400 when a required parameter is missing
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 if the apikey is not found
     *          HTTP 406 if a response MIME type other than application/JSON was requested
     *          HTTP 410 if the apikey is invalidated / deprecated
     *          HTTP 415 if the submitted request does not contain a valid JSON body
     */
    @CrossOrigin(maxAge = 600)
    @RequestMapping(method   = RequestMethod.PUT,
                    produces = MediaType.APPLICATION_JSON_VALUE,
                    consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> update(@RequestBody ApikeyUpdate apikeyUpdate) {
        LOG.debug("update registration details for apikey: {}", apikeyUpdate.getApikey());
        String missing = mandatoryMissing(apikeyUpdate);
        if (!missing.equals("")){
            LOG.debug(missing + ", aborting registration details update");
            return new ResponseEntity<>(new ApikeyException(400, "missing parameter", missing), HttpStatus.BAD_REQUEST);
        }
        HttpHeaders headers = new HttpHeaders();

        // retrieve apikey & check if available
        Apikey apikey = this.apikeyRepo.findOne(apikeyUpdate.getApikey());
        if (null == apikey) {
            LOG.debug("apikey: {} not found", apikeyUpdate.getApikey());
            headers.add("Apikey-not-found", "apikey-not-found");
            return new ResponseEntity<>(headers, HttpStatus.NOT_FOUND);
        } else {
            LOG.debug("update registration details for apikey: {}", apikey.getApikey());
        }

        // check if apikey is deprecated (deprecationDate != null & in the past)
        if (null != apikey.getDeprecationDate() && apikey.getDeprecationDate().before(new Date())) {
            LOG.debug("apikey {} is deprecated", apikeyUpdate.getApikey());
            return new ResponseEntity<>(HttpStatus.GONE);
        }
        apikey = copyUpdateValues(apikey, apikeyUpdate);
        this.apikeyRepo.save(apikey);
        return new ResponseEntity<>(apikey, headers, HttpStatus.OK);
    }

    /**
     * Re-enables a given invalid Apikey (of which the deprecationdate column has been set to a past time).
     * NOTE that for now the code does not check if the key is really deprecated; it merely executes the update (if any)
     * in such cases.
     *
     * @param   id the apikey to re-enable
     * @param   apikeyUpdate RequestBody containing supplied values
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in apikey.java
     *          HTTP 200 upon successful Apikey update
     *          HTTP 400 when a required parameter is missing or (for 'Level') has an invalid value
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 if the apikey is not found
     *          HTTP 406 if a response MIME type other than application/JSON was requested
     *          HTTP 415 if the submitted request does not contain a valid JSON body
     */
    @RequestMapping(path = "/{id}", method = RequestMethod.POST,
                    produces = MediaType.APPLICATION_JSON_VALUE,
                    consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> reenable(@PathVariable("id") String id,
                                           @RequestBody(required = false) ApikeyUpdate apikeyUpdate ) {
        LOG.debug("re-enable invalidated apikey: {}", id);
        HttpHeaders headers = new HttpHeaders();

        // retrieve apikey & check if available
        Apikey apikey = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            LOG.debug("apikey: " + id + " not found");
            headers.add("Apikey-not-found", "apikey-not-found");
            return new ResponseEntity<>(headers, HttpStatus.NOT_FOUND);
        }
        // remove deprecationdate: this enables the key again
        apikey.setDeprecationDate(null);

        // update values if supplied
        if (null != apikeyUpdate) {
            String missing = mandatoryMissing(apikeyUpdate);
            if (!missing.equals("")){
                return new ResponseEntity<>(new ApikeyException(400, "missing parameter", missing), HttpStatus.BAD_REQUEST);
            }
            apikey = copyUpdateValues(apikey, apikeyUpdate);
        }
        this.apikeyRepo.save(apikey);
        return new ResponseEntity<>(apikey, headers, HttpStatus.OK);
     }



    /**
     * Invalidate a given Apikey. This is done by setting the deprecationdate column to the current time; the data
     * remain available in the database
     *
     * @param   id the apikey to invalidate
     * @return  HTTP 204 upon successful execution
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 when the requested Apikey is not found in the database
     *          HTTP 410 when the requested Apikey is deprecated (i.e. has a past deprecationdate)
     *
     * Addionally, the field 'Apikey-not-found' containing the string "apikey-not-found" will be available in the
     * response header to help telling this HTTP 404 apart from one returned by the webserver for other reasons
     */
    @CrossOrigin(maxAge = 600)
    @RequestMapping(path = "/{id}", method = RequestMethod.DELETE)
    public ResponseEntity<String> delete(@PathVariable("id") String id) {
        LOG.debug("invalidate apikey: {}", id);
        Apikey      apikey  = this.apikeyRepo.findOne(id);
        HttpHeaders headers = new HttpHeaders();

        // check if apikey exists
        if (null == apikey) {
            LOG.debug("apikey: " + id + " not found");
            headers.add("Apikey-not-found", "apikey-not-found");
            return new ResponseEntity<>(headers, HttpStatus.NOT_FOUND);
        }

        // check if apikey is deprecated (deprecationDate != null & in the past)
        if (null != apikey.getDeprecationDate() && apikey.getDeprecationDate().before(new Date())) {
            LOG.debug("apikey {} is deprecated", id);
            return new ResponseEntity<>(HttpStatus.GONE);
        }

        apikey.setDeprecationDate(new DateTime(DateTimeZone.UTC).toDate());
        this.apikeyRepo.save(apikey);
        return new ResponseEntity<>(headers, HttpStatus.NO_CONTENT);
    }

    /**
     * Retrieves the details associated with the registration of a given Apikey
     *
     * @param   id the apikey to retrieve
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in apikey.java
     *          HTTP 200 upon successful execution
     *          HTTP 404 when the requested Apikey is not found in the database
     *          HTTP 406 if a MIME type other than application/JSON was requested
     */
    @CrossOrigin(maxAge = 600)
    @JsonView(View.Public.class)
    @RequestMapping(path = "/{id}", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Apikey> get(@PathVariable("id") String id) {
        LOG.debug("retrieve details for apikey: {}", id);
        HttpHeaders headers = new HttpHeaders();
        Apikey      apikey  = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            LOG.debug("apikey: " + id + " not found");
            headers.add("Apikey-not-found", "apikey-not-found");
            return new ResponseEntity<>(null, headers, HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(apikey, headers, HttpStatus.OK);
    }

    /**
     * Validates a given Apikey. Sets last access date and activation date (if not set, ie. first access) with the
     * current date and +1 increments the usage count of this Apikey.
     *
     * @param   id     the apikey to validate
     * @param   api    API for which validate this apikey
     * @param   method method (read, write) for which validate this apikey
     *
     * @return  HTTP 204 upon successful validation
     *          HTTP 400 if a mandatory parameter is missing
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 when the requested Apikey is not found in the database
     *          HTTP 410 when the requested Apikey is deprecated (i.e. has a past deprecationdate)
     *          HTTP 429 if the assigned usagelimit has been reached
     *          Addionally, the following fields are (optionally) available in the response header:
     *          - "X-RateLimit-Remaining" access usage number since the previous reset
     *          - "X-RateLimit-Reset"     the number of seconds until the access usage count is reset
     *          - "Apikey-not-found"      containing the string "apikey-not-found" is added when the Apikey
     *                                    is not found, to help telling this HTTP 404 apart from one returned
     *                                    by the webserver for other reasons
     */
    @RequestMapping(path = "/{id}/validate", method = RequestMethod.POST)
    public ResponseEntity<Apikey> validate(@PathVariable("id") String id,
                                           @RequestParam(value = "api", required = false) String api,
                                           @RequestParam(value = "method", required = false) String method) {

        LOG.debug("validate apikey: {}", id);
        ApiName     apiName; //TODO usage not implemented yet
        HttpHeaders headers  = new HttpHeaders();
        DateTime    nowDtUtc = new DateTime(DateTimeZone.UTC);
        Date        now      = nowDtUtc.toDate();

        if (!StringUtils.isEmpty(api)) {
            try {
                apiName = ApiName.valueOf(api.toUpperCase().trim());
            } catch (IllegalArgumentException e) {
                LOG.debug("illegal value for parameter 'api': {}", api);
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
        } else {
            LOG.debug("no value for parameter 'api' supplied");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        if (!StringUtils.isEmpty(method)) {
            LOG.debug("no value for parameter 'method' supplied");
            if (!method.equalsIgnoreCase(READ) && !method.equalsIgnoreCase(WRITE)) {
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
        }

        // retrieve apikey & check if available
        Apikey apikey = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            LOG.debug("apikey {} not found", id);
            headers.add("Apikey-not-found", "apikey-not-found");
            return new ResponseEntity<>(headers, HttpStatus.NOT_FOUND);
        }

        // check if not deprecated (deprecationDate != null & in the past)
        if (null != apikey.getDeprecationDate() && apikey.getDeprecationDate().before(new Date())) {
            LOG.debug("apikey {} is deprecated", id);
            return new ResponseEntity<>(HttpStatus.GONE);
        }

        // set activationDate = sysdate if null
        if (null == apikey.getActivationDate()) {
            apikey.setActivationDate(now);
        }

        // set lastAccessDate = sysdate
        apikey.setLastAccessDate(now);

        // (mock-)check usage
        long usage     = apikey.getUsage();
        long remaining = apikey.getUsageLimit() - usage;
        headers.add("X-RateLimit-Reset",
                    String.valueOf(new Duration(nowDtUtc,
                                                nowDtUtc.plusDays(1).withTimeAtStartOfDay()).toStandardSeconds()
                                                                                            .getSeconds()));

        if (remaining <= 0L) {
            // You shall not pass!
            headers.add("X-RateLimit-Remaining", String.valueOf(0));
            LOG.debug("usage limit of apikey {} reached", id);
            return new ResponseEntity<>(headers, HttpStatus.TOO_MANY_REQUESTS);
        } else {
            // Welcome, gringo!
            headers.add("X-RateLimit-Remaining", String.valueOf(remaining - 1));
            apikey.setUsage(usage + 1);
            this.apikeyRepo.save(apikey);
            return new ResponseEntity<>(headers, HttpStatus.NO_CONTENT);
        }
    }

    // created to facilitate Rene's testing
    @RequestMapping(path = "/{id}/set", method = RequestMethod.PUT)
    public ResponseEntity<Apikey> validate(@PathVariable("id") String id,
                                           @RequestParam(value = "limit", required = false) Long limit,
                                           @RequestParam(value = "reset", required = false) Boolean reset,
                                           @RequestParam(value = "deprecated", required = false) Boolean deprecated) {

        Date lastWeek = new DateTime(DateTimeZone.UTC).minusDays(7).toDate();

        Apikey apikey = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        // if reset == true: reset usage to zero
        if (null != reset && reset) {
            apikey.setUsage(0L);
        }
        // if limit is set: reset usageLimit to limit
        if (null != limit) {
            apikey.setUsageLimit(limit);
        }
        // if deprecate == true: set dateDeprecated to last week; if false, set null
        if (null != deprecated && deprecated) {
            apikey.setDeprecationDate(lastWeek);
        } else if (null != deprecated && !deprecated) {
            apikey.setDeprecationDate(null);
        }

        if (null == reset && null == deprecated && null == limit) {
            return new ResponseEntity<>(HttpStatus.I_AM_A_TEAPOT); // HTTP 418
        } else {
            this.apikeyRepo.save(apikey);
            return new ResponseEntity<>(HttpStatus.ACCEPTED); // HTTP 202
        }
    }

    private Apikey copyUpdateValues(Apikey apikey, ApikeyUpdate apikeyUpdate){
        if (null != apikeyUpdate.getFirstName()) {
            apikey.setFirstName(apikeyUpdate.getFirstName());
        }
        if (null != apikeyUpdate.getLastName()) {
            apikey.setLastName(apikeyUpdate.getLastName());
        }
        if (null != apikeyUpdate.getEmail()) {
            apikey.setEmail(apikeyUpdate.getEmail());
        }
        if (null != apikeyUpdate.getWebsite()) {
            apikey.setWebsite(apikeyUpdate.getWebsite());
        }
        if (null != apikeyUpdate.getAppName()) {
            apikey.setAppName(apikeyUpdate.getAppName());
        }
        if (null != apikeyUpdate.getCompany()) {
            apikey.setCompany(apikeyUpdate.getCompany());
        }
        if (null != apikeyUpdate.getSector()) {
            apikey.setSector(apikeyUpdate.getSector());
        }
        return apikey;
    }

    private String mandatoryMissing(ApikeyAction apikeyUpdate){
        String retval = "required parameter";
        ArrayList<String> missingList = new ArrayList<>();
        if (null == apikeyUpdate.getFirstName()) missingList.add("'firstName'");
        if (null == apikeyUpdate.getLastName()) missingList.add("'lastName'");
        if (null == apikeyUpdate.getEmail()) missingList.add("'email'");
        if (missingList.size() == 3) {
            retval += "s " + missingList.get(0) + ", " + missingList.get(1) + " and " + missingList.get(2);
        } else if (missingList.size() == 2) {
            retval += "s " + missingList.get(0) + " and " + missingList.get(1);
        } else if (missingList.size() == 1) {
            retval += " " + missingList.get(0);
        } else {
            return "";
        }
        return retval + " not provided";
    }


}
