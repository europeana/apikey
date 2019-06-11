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
import eu.europeana.apikey.keycloak.KeycloakAuthenticationToken;
import eu.europeana.apikey.keycloak.KeycloakManager;
import eu.europeana.apikey.keycloak.KeycloakSecurityContext;
import eu.europeana.apikey.mail.MailServiceImpl;
import eu.europeana.apikey.repos.ApikeyRepo;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/apikey")
public class ApikeyController {
    private final ApikeyRepo apikeyRepo;
    private static final String READ  = "read";
    private static final String WRITE = "write";
    private static final Logger LOG   = LogManager.getLogger(ApikeyController.class);
    private static final String MISSINGPARAMETER = "missing parameter";
    private static final String APIKEYNOTFOUND = "Apikey-not-found";
    private static final String APIKEYDEPRECATED = "apikey {} is deprecated";
    private static final String APIKEYNOTREGISTERED = "Apikey {} is not registered";
    private static final String APIKEYMISSING = "Missing apikey in the header. Correct syntax: Authorization: APIKEY apikey";
    private static final String APIKEY_PATTERN = "APIKEY\\s+([^\\s]+)";

    @Autowired
    public ApikeyController(ApikeyRepo apikeyRepo) {
        this.apikeyRepo = apikeyRepo;
    }

    @Autowired
    public MailServiceImpl emailService;


    @Autowired
    public SimpleMailMessage apikeyCreatedMail;


    @Autowired
    private KeycloakManager keycloakManager;

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
     *          HTTP 400 when a required parameter is missing or has an invalid value
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
    public ResponseEntity<Object> save(@RequestBody ApikeyDetails apikeyCreate) {
        LOG.debug("creating new apikey");
        String missing = mandatoryMissing(apikeyCreate);
        if (!missing.equals("")){
            LOG.debug(missing + ", abort creating apikey");
            return new ResponseEntity<>(new ApikeyException(400, MISSINGPARAMETER, missing), HttpStatus.BAD_REQUEST);
        }

        KeycloakAuthenticationToken keycloakAuthenticationToken = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        KeycloakSecurityContext securityContext = (KeycloakSecurityContext) keycloakAuthenticationToken.getCredentials();
        try {
            FullApikey apikey = keycloakManager.createClient(securityContext, apikeyCreate);
            if (apikey != null) {
                this.apikeyRepo.save(new Apikey(apikey));
                LOG.debug("apikey: {} created", apikey.getApikey());

                emailService.sendSimpleMessageUsingTemplate(apikey.getEmail(),
                        "Your Europeana API keys",
                        apikeyCreatedMail,
                        apikey.getFirstName(),
                        apikey.getLastName(),
                        apikey.getApikey(),
                        apikey.getClientSecret());
                return new ResponseEntity<>(apikey, HttpStatus.CREATED);
            }
        } catch (ApikeyException e) {
            return new ResponseEntity<>(e, HttpStatus.valueOf(e.getStatus()));
        }
        return new ResponseEntity<>(new ApikeyException(400, MISSINGPARAMETER, missing), HttpStatus.BAD_REQUEST);
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
     * @param   id PathParam containing api key to be updated
     * @param   apikeyUpdate RequestBody containing supplied values
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in apikey.java
     *          HTTP 200 upon successful Apikey update
     *          HTTP 400 when a required parameter is missing
     *          HTTP 401 in case of an unauthorized request (client credential authentication fails)
     *          HTTP 403 if the request is unauthorised (when the client is not a manager)
     *          HTTP 404 if the apikey is not found
     *          HTTP 406 if a response MIME type other than application/JSON was requested
     *          HTTP 410 if the apikey is invalidated / deprecated
     *          HTTP 415 if the submitted request does not contain a valid JSON body
     */
    @CrossOrigin(maxAge = 600)
    @PutMapping(value = "/{id}",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> update(@PathVariable("id") String id, @RequestBody ApikeyDetails apikeyUpdate) {
        LOG.debug("update registration details for apikey: {}", id);
        String missing = mandatoryMissing(apikeyUpdate);
        if (!missing.equals("")){
            LOG.debug(missing + ", aborting registration details update");
            return new ResponseEntity<>(new ApikeyException(400, MISSINGPARAMETER, missing), HttpStatus.BAD_REQUEST);
        }
        HttpHeaders headers = new HttpHeaders();

        // retrieve apikey & check if available
        Apikey apikey = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            LOG.debug("apikey: {} not found", id);
            headers.add(APIKEYNOTFOUND, APIKEYNOTFOUND.toLowerCase());
            return new ResponseEntity<>(headers, HttpStatus.NOT_FOUND);
        } else {
            LOG.debug("update registration details for apikey: {}", apikey.getApikey());
        }

        // check if apikey is deprecated (deprecationDate != null & in the past)
        if (null != apikey.getDeprecationDate() && apikey.getDeprecationDate().before(new Date())) {
            LOG.debug(APIKEYDEPRECATED, id);
            return new ResponseEntity<>(HttpStatus.GONE);
        }

        KeycloakAuthenticationToken keycloakAuthenticationToken = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        if (!keycloakManager.isClientAuthorized(apikey.getApikey(), keycloakAuthenticationToken, true)) {
            return new ResponseEntity<>(headers, HttpStatus.FORBIDDEN);
        }

        try {
            keycloakManager.updateClient((KeycloakSecurityContext) keycloakAuthenticationToken.getCredentials(), apikeyUpdate, id);
            copyUpdateValues(apikey, apikeyUpdate);
            this.apikeyRepo.save(apikey);
        } catch (RuntimeException e) {
            LOG.error("Error saving to DB", e);
            return new ResponseEntity<>(headers, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (ApikeyException e) {
            LOG.error("Could not update client", e);
            return new ResponseEntity<>(e, HttpStatus.valueOf(e.getStatus()));
        }
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
     *          HTTP 400 when a required parameter is missing or has an invalid value
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 if the apikey is not found
     *          HTTP 406 if a response MIME type other than application/JSON was requested
     *          HTTP 415 if the submitted request does not contain a valid JSON body
     */
    @PostMapping(path = "/{id}",
                    produces = MediaType.APPLICATION_JSON_VALUE,
                    consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> reenable(@PathVariable("id") String id,
                                           @RequestBody(required = false) ApikeyDetails apikeyUpdate ) {
        LOG.debug("re-enable invalidated apikey: {}", id);
        KeycloakAuthenticationToken keycloakAuthenticationToken = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        if (!keycloakManager.isClientAuthorized(id, keycloakAuthenticationToken, true)) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }

        HttpHeaders headers = new HttpHeaders();

        // retrieve apikey & check if available
        Apikey apikey = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            LOG.debug(APIKEYNOTFOUND + " with value: " + id);
            headers.add(APIKEYNOTFOUND, APIKEYNOTFOUND.toLowerCase());
            return new ResponseEntity<>(headers, HttpStatus.NOT_FOUND);
        }

        try {
            // update values if supplied
            if (null != apikeyUpdate) {
                String missing = mandatoryMissing(apikeyUpdate);
                if (!missing.equals("")) {
                    return new ResponseEntity<>(new ApikeyException(400, MISSINGPARAMETER, missing), HttpStatus.BAD_REQUEST);
                }
                copyUpdateValues(apikey, apikeyUpdate);
            }
            keycloakManager.enableClient(true, id, apikeyUpdate, (KeycloakSecurityContext) keycloakAuthenticationToken.getCredentials());
            // remove deprecationdate: this enables the key again
            apikey.setDeprecationDate(null);
            this.apikeyRepo.save(apikey);
        } catch (RuntimeException e) {
            LOG.error("Error saving to DB", e);
            return new ResponseEntity<>(headers, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (ApikeyException e) {
            LOG.error("Could not reenable a client", e);
            return new ResponseEntity<>(e, HttpStatus.valueOf(e.getStatus()));
        }

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
    @DeleteMapping(path = "/{id}")
    public ResponseEntity<String> delete(@PathVariable("id") String id) {
        KeycloakAuthenticationToken keycloakAuthenticationToken = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        if (!keycloakManager.isClientAuthorized(id, keycloakAuthenticationToken, true)) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }

        LOG.debug("invalidate apikey: {}", id);
        Apikey      apikey  = this.apikeyRepo.findOne(id);
        HttpHeaders headers = new HttpHeaders();

        // check if apikey exists
        if (null == apikey) {
            LOG.debug(APIKEYNOTFOUND + " with value: " + id);
            headers.add(APIKEYNOTFOUND, APIKEYNOTFOUND.toLowerCase());
            return new ResponseEntity<>(headers, HttpStatus.NOT_FOUND);
        }

        // check if apikey is deprecated (deprecationDate != null & in the past)
        if (null != apikey.getDeprecationDate() && apikey.getDeprecationDate().before(new Date())) {
            LOG.debug(APIKEYDEPRECATED, id);
            return new ResponseEntity<>(HttpStatus.GONE);
        }

        try {
            keycloakManager.enableClient(false, id, null, (KeycloakSecurityContext) keycloakAuthenticationToken.getCredentials());
            apikey.setDeprecationDate(new DateTime(DateTimeZone.UTC).toDate());
            this.apikeyRepo.save(apikey);
        } catch (RuntimeException e) {
            LOG.error("Error saving to DB", e);
            return new ResponseEntity<>(headers, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (ApikeyException e) {
            LOG.error("Could not delete a client", e);
            return new ResponseEntity<>("Could not delete a client", HttpStatus.valueOf(e.getStatus()));
        }
        return new ResponseEntity<>(headers, HttpStatus.NO_CONTENT);
    }

    /**
     * Retrieves the details associated with the registration of a given Apikey
     *
     * @param   id the apikey to retrieve
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in apikey.java
     *          HTTP 200 upon successful execution
     *          HTTP 401 When reqested api key does not belong to the authenticated client or this client is not a manager client
     *          HTTP 404 when the requested Apikey is not found in the database
     *          HTTP 406 if a MIME type other than application/JSON was requested
     */
    @CrossOrigin(maxAge = 600)
    @JsonView(View.Public.class)
    @GetMapping(path = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Apikey> get(@PathVariable("id") String id) {
        LOG.debug("retrieve details for apikey: {}", id);
        HttpHeaders headers = new HttpHeaders();

        Apikey      apikey  = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            LOG.debug(APIKEYNOTFOUND + " with value: " + id);
            headers.add(APIKEYNOTFOUND, id);
            return new ResponseEntity<>(headers, HttpStatus.NOT_FOUND);
        }

        KeycloakAuthenticationToken keycloakAuthenticationToken = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        if (!keycloakManager.isClientAuthorized(apikey.getApikey(), keycloakAuthenticationToken, false)) {
            return new ResponseEntity<>(headers, HttpStatus.UNAUTHORIZED);
        }
        return new ResponseEntity<>(apikey, headers, HttpStatus.OK);
    }

    /**
     * Validates a given Apikey. Sets last access date and activation date (if not set, ie. first access) with the
     * current date and +1 increments the usage count of this Apikey.
     *
     * @param   httpServletRequest     request
     *
     * @return  HTTP 204 upon successful validation
     *          HTTP 400 bad request when header does not contain api key
     *          HTTP 401 in case of an unregistered api key
     *          HTTP 410 when the requested Apikey is deprecated (i.e. has a past deprecationdate)
     */
    @PostMapping(path = "/validate")
    public ResponseEntity<Apikey> validate(HttpServletRequest httpServletRequest) {
        // When no apikey was supplied return 400
        String id = getApikey(httpServletRequest);
        if (null == id) {
            LOG.debug(APIKEYMISSING);
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        LOG.debug("validate apikey: {}", id);

        // retrieve apikey & check if available
        Apikey apikey = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            LOG.debug(APIKEYNOTREGISTERED, id);
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        // check if not deprecated (deprecationDate != null & in the past)
        if (null != apikey.getDeprecationDate() && apikey.getDeprecationDate().before(new Date())) {
            LOG.debug(APIKEYDEPRECATED, id);
            return new ResponseEntity<>(HttpStatus.GONE);
        }

        Date now = new DateTime(DateTimeZone.UTC).toDate();

        // set activationDate = sysdate if null
        if (null == apikey.getActivationDate()) {
            apikey.setActivationDate(now);
        }

        // set lastAccessDate = sysdate
        apikey.setLastAccessDate(now);
        this.apikeyRepo.save(apikey);

        // Welcome, gringo!
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    private String getApikey(HttpServletRequest httpServletRequest) {
        String authorization = httpServletRequest.getHeader("Authorization");
        if (authorization != null) {
            String patternString = APIKEY_PATTERN;

            Pattern pattern = Pattern.compile(patternString);
            Matcher matcher = pattern.matcher(authorization);

            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return null;
    }

    // created to facilitate Rene's testing
    @RequestMapping(path = "/{id}/set", method = RequestMethod.PUT)
    public ResponseEntity<Apikey> validate(@PathVariable("id") String id,
                                           @RequestParam(value = "reset", required = false) Boolean reset,
                                           @RequestParam(value = "deprecated", required = false) Boolean deprecated) {

        Date lastWeek = new DateTime(DateTimeZone.UTC).minusDays(7).toDate();

        Apikey apikey = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        // if deprecated == true: set dateDeprecated to last week; if false, set null
        if (BooleanUtils.isTrue(deprecated)){
            apikey.setDeprecationDate(lastWeek);
        } else if (BooleanUtils.isFalse(deprecated)) {
            apikey.setDeprecationDate(null);
        }

        if (null == reset && null == deprecated) {
            return new ResponseEntity<>(HttpStatus.I_AM_A_TEAPOT); // HTTP 418
        } else {
            this.apikeyRepo.save(apikey);
            return new ResponseEntity<>(HttpStatus.ACCEPTED); // HTTP 202
        }
    }

//    @CrossOrigin(maxAge = 600)
    @RequestMapping(path = "", method = RequestMethod.GET)
    public String helloWorld() {
        LOG.debug("hello world endpoint");
        return "Hello World!";
    }

    private Apikey copyUpdateValues(Apikey apikey, ApikeyDetails apikeyUpdate){
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
