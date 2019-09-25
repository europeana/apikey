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
import eu.europeana.apikey.captcha.CaptchaManager;
import eu.europeana.apikey.domain.*;
import eu.europeana.apikey.keycloak.CustomKeycloakAuthenticationProvider;
import eu.europeana.apikey.keycloak.KeycloakAuthenticationToken;
import eu.europeana.apikey.keycloak.KeycloakManager;
import eu.europeana.apikey.keycloak.KeycloakSecurityContext;
import eu.europeana.apikey.mail.MailServiceImpl;
import eu.europeana.apikey.repos.ApikeyRepo;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import java.util.ArrayList;
import java.util.Date;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/apikey")
public class ApikeyController {
    private final ApikeyRepo apikeyRepo;
    private static final Logger LOG   = LogManager.getLogger(ApikeyController.class);
    private static final String MISSINGPARAMETER = "missing parameter";
    private static final String BAD_EMAIL_FORMAT = "Email is not properly formatted.";
    private static final String APIKEYNOTFOUND = "API key %s does not exist.";
    private static final String APIKEYDEPRECATED = "API key %s is deprecated";
    private static final String APIKEYNOTREGISTERED = "API key %s is not registered";
    private static final String APIKEYMISSING = "Missing apikey in the header. Correct syntax: Authorization: APIKEY apikey";
    private static final String APIKEY_PATTERN = "APIKEY\\s+([^\\s]+)";
    private static final String CAPTCHA_PATTERN = "Bearer\\s+([^\\s]+)";
    private static final String CAPTCHA_MISSING = "Missing Captcha token in the header. Correct syntax: Authorization: Bearer CAPTCHA_TOKEN";
    private static final String CAPTCHA_VERIFICATION_FAILED = "Captcha verification failed.";
    private static final String NOT_FOUND_ERROR = "Not found";

    @Value("${keycloak.manager-client-id}")
    private String managerClientId;

    @Value("${keycloak.manager-client-secret}")
    private String managerClientSecret;

    private final CaptchaManager captchaManager;

    private final CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;

    private final MailServiceImpl emailService;

    private final SimpleMailMessage apikeyCreatedMail;

    private final KeycloakManager keycloakManager;

    @Autowired
    public ApikeyController(ApikeyRepo apikeyRepo, CaptchaManager captchaManager, CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider, MailServiceImpl emailService, SimpleMailMessage apikeyCreatedMail, KeycloakManager keycloakManager) {
        this.apikeyRepo = apikeyRepo;
        this.captchaManager = captchaManager;
        this.customKeycloakAuthenticationProvider = customKeycloakAuthenticationProvider;
        this.emailService = emailService;
        this.apikeyCreatedMail = apikeyCreatedMail;
        this.keycloakManager = keycloakManager;
    }


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
    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE,
                    consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> save(@RequestBody ApikeyDetails apikeyCreate) {
        LOG.debug("creating new apikey");
        try {
            mandatoryMissing(apikeyCreate);
        } catch (ApikeyException e) {
            LOG.debug(e.getMessage() + ", abort creating apikey");
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
        KeycloakAuthenticationToken keycloakAuthenticationToken = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        return createClient(apikeyCreate, (KeycloakSecurityContext) keycloakAuthenticationToken.getCredentials());
    }

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
     * The Apikey field is generated: Apikey is a unique and random 'readable' lowercase string,
     * 8 to 12 characters long, e.g. 'rhossindri', 'viancones' or 'ebobrent'. The method is protected with
     * captcha token supplied in the Authorization header.
     *
     * Upon successful execution, the code will send an email message containing the Apikey and secret generated
     * by Kyecloak to the email address supplied in the request.
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
    @CrossOrigin(maxAge = 600)
    @PostMapping(path = "/captcha",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> altSave(HttpServletRequest httpServletRequest, @RequestBody ApikeyDetails apikeyCreate) {
        LOG.debug("creating new apikey secured by captcha");

        // When no captcha token was supplied return 401
        String captchaToken = getAuthorizationHeader(httpServletRequest, CAPTCHA_PATTERN);
        if (null == captchaToken) {
            LOG.debug(CAPTCHA_MISSING);
            return new ResponseEntity<>(CAPTCHA_MISSING, HttpStatus.UNAUTHORIZED);
        }

        // Captcha verification, when failed return 403
        try {
            if (!captchaManager.verifyCaptchaToken(captchaToken)) {
                LOG.debug(CAPTCHA_VERIFICATION_FAILED + ", abort creating apikey");
                return new ResponseEntity<>(CAPTCHA_VERIFICATION_FAILED, HttpStatus.UNAUTHORIZED);
            }
        } catch (ApikeyException e) {
            LOG.debug(e.getError() + ", abort creating apikey");
            return new ResponseEntity<>(e.getError(), HttpStatus.UNAUTHORIZED);
        }

        try {
            mandatoryMissing(apikeyCreate);
        } catch (ApikeyException e) {
            LOG.debug(e.getMessage() + ", abort creating apikey");
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        // authenticate manager client to get the access token
        KeycloakAuthenticationToken authenticationToken = (KeycloakAuthenticationToken) customKeycloakAuthenticationProvider.authenticate(managerClientId, managerClientSecret);
        if (authenticationToken == null) {
            return new ResponseEntity<>("Operation forbidden.", HttpStatus.FORBIDDEN);
        }

        return createClient(apikeyCreate, (KeycloakSecurityContext) authenticationToken.getCredentials());
    }

    /**
     * Create client based on the details supplied in the request. Security context is used for creating client in
     * Keycloak. When this succeeds the client information is save in the local database and sent to the supplied
     * email.
     *
     * @param apikeyCreate details to be used for the created client
     * @param securityContext security context neede for authorization in Keycloak
     * @return response with created Apikey details
     */
    private ResponseEntity<Object> createClient(@RequestBody ApikeyDetails apikeyCreate, KeycloakSecurityContext securityContext) {
        try {
            FullApikey apikey = keycloakManager.createClient(securityContext, apikeyCreate);
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
        } catch (ApikeyException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.valueOf(e.getStatus()));
        }
    }

    /**
     * Get value from the Authorization header of the given request based on the supplied pattern.
     *
     * @param httpServletRequest request with the header
     * @param valuePattern pattern of the Authorization header to retrieve the value
     * @return value of the Authorization header
     */
    private String getAuthorizationHeader(HttpServletRequest httpServletRequest, String valuePattern) {
        String authorization = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null) {

            try {
                Pattern pattern = Pattern.compile(valuePattern);
                Matcher matcher = pattern.matcher(authorization);

                if (matcher.find()) {
                    return matcher.group(1);
                }
            } catch (RuntimeException e) {
                LOG.error("Regex problem while parsing authorization header", e);
            }
        }
        return null;
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
        try {
            mandatoryMissing(apikeyUpdate);
        } catch (ApikeyException e) {
            LOG.debug(e.getMessage() + ", aborting registration details update");
            return new ResponseEntity<>(e, HttpStatus.BAD_REQUEST);
        }

        HttpHeaders headers = new HttpHeaders();

        // retrieve apikey & check if available
        Apikey apikey = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            LOG.debug(String.format(APIKEYNOTFOUND, id));
            return new ResponseEntity<>(new ApikeyException(HttpStatus.NOT_FOUND.value(), NOT_FOUND_ERROR, String.format(APIKEYNOTFOUND, id)), HttpStatus.NOT_FOUND);
        } else {
            LOG.debug("update registration details for apikey: {}", apikey.getApikey());
        }

        // check if apikey is deprecated (deprecationDate != null & in the past)
        if (null != apikey.getDeprecationDate() && apikey.getDeprecationDate().before(new Date())) {
            LOG.debug(String.format(APIKEYDEPRECATED, id));
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
            LOG.debug(String.format(APIKEYNOTFOUND, id));
            return new ResponseEntity<>(new ApikeyException(HttpStatus.NOT_FOUND.value(), NOT_FOUND_ERROR, String.format(APIKEYNOTFOUND, id)), HttpStatus.NOT_FOUND);
        }

        try {
            // update values if supplied
            if (null != apikeyUpdate) {
                try {
                    mandatoryMissing(apikeyUpdate);
                } catch (ApikeyException e) {
                    return new ResponseEntity<>(e, HttpStatus.BAD_REQUEST);
                }
                apikey = copyUpdateValues(apikey, apikeyUpdate);
            }
            if (!requestFromKeycloak(keycloakAuthenticationToken)) {
                // call Keycloak update only when this request does not come from Keycloak
                keycloakManager.enableClient(true, id, apikeyUpdate, (KeycloakSecurityContext) keycloakAuthenticationToken.getCredentials());
            }
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

    private boolean requestFromKeycloak(KeycloakAuthenticationToken keycloakAuthenticationToken) {
        return keycloakAuthenticationToken.getAuthorities()
                .stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("synchronize"));
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
    public ResponseEntity<Object> delete(@PathVariable("id") String id) {
        KeycloakAuthenticationToken keycloakAuthenticationToken = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        if (!keycloakManager.isClientAuthorized(id, keycloakAuthenticationToken, true)) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }

        LOG.debug("invalidate apikey: {}", id);
        Apikey      apikey  = this.apikeyRepo.findOne(id);
        HttpHeaders headers = new HttpHeaders();

        // check if apikey exists
        if (null == apikey) {
            LOG.debug(String.format(APIKEYNOTFOUND, id));
            return new ResponseEntity<>(new ApikeyException(HttpStatus.NOT_FOUND.value(), NOT_FOUND_ERROR, String.format(APIKEYNOTFOUND, id)), HttpStatus.NOT_FOUND);
        }

        // check if apikey is deprecated (deprecationDate != null & in the past)
        if (null != apikey.getDeprecationDate() && apikey.getDeprecationDate().before(new Date())) {
            LOG.debug(String.format(APIKEYDEPRECATED, id));
            return new ResponseEntity<>(HttpStatus.GONE);
        }

        try {
            if (!requestFromKeycloak(keycloakAuthenticationToken)) {
                keycloakManager.enableClient(false, id, null, (KeycloakSecurityContext) keycloakAuthenticationToken.getCredentials());
            }
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
     * This is request for removing the api key completely from the service. It may be executed only by the privileged client
     * representing synchronization procedure in Keycloak.
     *
     * @param id api key identifier from Keycloak
     * @return  HTTP 204 upon successful execution
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 when the requested keycloak identifier is not found in the database
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/synchronize/{keycloakid}")
    public ResponseEntity<String> deleteCompletely(@PathVariable("keycloakid") String id) {
        KeycloakAuthenticationToken keycloakAuthenticationToken = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        if (!keycloakManager.isClientAuthorized(id, keycloakAuthenticationToken, true) ||
                !requestFromKeycloak(keycloakAuthenticationToken)) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }

        Optional<Apikey> optionalApikey = this.apikeyRepo.findByKeycloakId(id);
        if (optionalApikey.isPresent()) {
            this.apikeyRepo.delete(optionalApikey.get());
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
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
    public ResponseEntity<Object> get(@PathVariable("id") String id) {
        LOG.debug("retrieve details for apikey: {}", id);
        HttpHeaders headers = new HttpHeaders();

        Apikey      apikey  = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            LOG.debug(String.format(APIKEYNOTFOUND, id));
            return new ResponseEntity<>(new ApikeyException(HttpStatus.NOT_FOUND.value(), NOT_FOUND_ERROR, String.format(APIKEYNOTFOUND, id)), HttpStatus.NOT_FOUND);
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
    public ResponseEntity<Object> validate(HttpServletRequest httpServletRequest) {
        // When no apikey was supplied return 400
        String id = getAuthorizationHeader(httpServletRequest, APIKEY_PATTERN);
        if (null == id) {
            LOG.debug(APIKEYMISSING);
            return new ResponseEntity<>(APIKEYMISSING, HttpStatus.BAD_REQUEST);
        }

        LOG.debug("validate apikey: {}", id);

        // retrieve apikey & check if available
        Apikey apikey = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            String reason = String.format(APIKEYNOTREGISTERED, id);
            LOG.debug(reason);
            return new ResponseEntity<>(reason, HttpStatus.UNAUTHORIZED);
        }

        // check if not deprecated (deprecationDate != null & in the past)
        if (null != apikey.getDeprecationDate() && apikey.getDeprecationDate().before(new Date())) {
            String reason = String.format(APIKEYDEPRECATED, id);
            LOG.debug(reason);
            return new ResponseEntity<>(reason, HttpStatus.GONE);
        }

        Date now = new DateTime(DateTimeZone.UTC).toDate();

        // set activationDate = sysdate if null
        if (null == apikey.getActivationDate()) {
            apikey.setActivationDate(now);
        }

        try {
            // set lastAccessDate = sysdate
            apikey.setLastAccessDate(now);
            this.apikeyRepo.save(apikey);
        } catch (RuntimeException e) {
            LOG.error("Error saving to DB", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

        // Welcome, gringo!
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
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

    private void mandatoryMissing(ApikeyAction apikeyUpdate) throws ApikeyException {
        String retval = "Required parameter(s): ";
        ArrayList<String> missingList = new ArrayList<>();
        if (null == apikeyUpdate.getFirstName()) missingList.add("'firstName'");
        if (null == apikeyUpdate.getLastName()) missingList.add("'lastName'");
        if (null == apikeyUpdate.getEmail()) missingList.add("'email'");

        if (!missingList.isEmpty()) {
            throw new ApikeyException(400, MISSINGPARAMETER, retval + missingList + " not provided");
        }

        if (!EmailValidator.getInstance().isValid(apikeyUpdate.getEmail())) {
            throw new ApikeyException(400, BAD_EMAIL_FORMAT, BAD_EMAIL_FORMAT);
        }
    }


}
