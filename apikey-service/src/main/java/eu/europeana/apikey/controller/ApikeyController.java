package eu.europeana.apikey.controller;

import com.fasterxml.jackson.annotation.JsonView;
import eu.europeana.apikey.captcha.CaptchaManager;
import eu.europeana.apikey.domain.*;
import eu.europeana.apikey.exception.*;
import eu.europeana.apikey.keycloak.CustomKeycloakAuthenticationProvider;
import eu.europeana.apikey.keycloak.KeycloakAuthenticationToken;
import eu.europeana.apikey.keycloak.KeycloakManager;
import eu.europeana.apikey.keycloak.KeycloakSecurityContext;
import eu.europeana.apikey.mail.MailService;
import eu.europeana.apikey.repos.ApikeyRepo;
import org.apache.commons.lang3.StringUtils;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handles all incoming requests
 * Authentication is done using Keycloak authentication, but additional constraints my be checked (for example if the
 * account is a manager account)
 *
 * Created by luthien on 18/04/2017.
 * Major refactoring by M. Helinski and Patrick Ehlert in September-November 2019
 */
@RestController
@RequestMapping("/apikey")
public class ApikeyController {

    private static final Logger LOG   = LogManager.getLogger(ApikeyController.class);

    private static final String MISSING_PARAMETER = "missing parameter";
    private static final String BAD_EMAIL_FORMAT = "Email is not properly formatted.";
    private static final String APIKEY_NOT_REGISTERED = "API key %s is not registered";
    private static final String APIKEY_MISSING = "Correct header syntax 'Authorization: APIKEY <your_key_here>'";
    private static final String APIKEY_PATTERN = "APIKEY\\s+([^\\s]+)";
    private static final String CAPTCHA_PATTERN = "Bearer\\s+([^\\s]+)";
    private static final String CAPTCHA_MISSING = "Missing Captcha token in the header. Correct syntax: Authorization: Bearer CAPTCHA_TOKEN";
    private static final String CAPTCHA_VERIFICATION_FAILED = "Captcha verification failed.";

    private final ApikeyRepo apikeyRepo;

    @Value("${keycloak.manager-client-id}")
    private String managerClientId;

    @Value("${keycloak.manager-client-secret}")
    private String managerClientSecret;

    private final CaptchaManager captchaManager;

    private final CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;

    private final MailService emailService;

    private final SimpleMailMessage apikeyCreatedMail;

    private final KeycloakManager keycloakManager;

    @Autowired
    public ApikeyController(ApikeyRepo apikeyRepo, CaptchaManager captchaManager, CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider,
                            MailService emailService, SimpleMailMessage apikeyCreatedMail, KeycloakManager keycloakManager) {
        this.apikeyRepo = apikeyRepo;
        this.captchaManager = captchaManager;
        this.customKeycloakAuthenticationProvider = customKeycloakAuthenticationProvider;
        this.emailService = emailService;
        this.apikeyCreatedMail = apikeyCreatedMail;
        this.keycloakManager = keycloakManager;
    }


    /**
     * Create a new Apikey with the following mandatory values supplied in a JSON request body:
     * - firstName
     * - lastName
     * - email
     * - appName
     * - company
     *
     * The following fields are optional:
     * - website
     * - sector
     *
     * The Apikey and Privatekey fields are generated: Apikey is a unique and random 'readable' lowercase string,
     * 8 to 12 characters long, e.g. 'rhossindri', 'viancones' or 'ebobrent'. Privatekey is a regular random string
     * mix of upper- and lowercase characters and numbers, eg. 'mh8Hvi6uXR' or 'Kts8H5ResV'.
     *
     * Upon successful execution, the code will send an email message containing the Apikey and Privatekey to the
     * email address supplied in the request.
     *
     * @param   newKeyRequest requestbody containing supplied values
     *
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in apikey.java
     *          HTTP 201 upon successful Apikey creation
     *          HTTP 400 when a required parameter is missing or has an invalid value
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 406 if a response MIME type other than application/JSON was requested
     *          HTTP 415 if the submitted request does not contain a valid JSON body
     *          HTTP 400 if apikey already exist for <email,appName>
     */
    @CrossOrigin(maxAge = 600)
    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity create(@RequestBody ApiKeyRequest newKeyRequest) throws ApiKeyException {
        LOG.debug("Creating new API key...");
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        checkMandatoryFields(newKeyRequest);
        checkKeyEmailAppNameExist(newKeyRequest.getEmail(), newKeyRequest.getAppName());
        return createClient(newKeyRequest, (KeycloakSecurityContext) kcAuthToken.getCredentials());
    }

    /**
     * Create a new API key with the following mandatory values supplied in a JSON request body:
     * - firstName
     * - lastName
     * - email
     * - appName
     * - company
     *
     * The following fields are optional:
     * - website
     * - sector
     *
     * The Apikey field is generated: Apikey is a unique and random 'readable' lowercase string,
     * 8 to 12 characters long, e.g. 'rhossindri', 'viancones' or 'ebobrent'. The method is protected with
     * captcha token supplied in the Authorization header.
     *
     * Upon successful execution, the code will send an email message containing the Apikey and secret generated
     * by Kyecloak to the email address supplied in the request.
     *
     * @param   newKeyRequest requestbody containing supplied values
     *
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in apikey.java
     *          HTTP 201 upon successful Apikey creation
     *          HTTP 400 when a required parameter is missing or has an invalid value
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 406 if a response MIME type other than application/JSON was requested
     *          HTTP 415 if the submitted request does not contain a valid JSON body
     *          HTTP 400 if apikey already exist for <email,appName>
     */
    @CrossOrigin(maxAge = 600)
    @PostMapping(path = "/captcha", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity createCaptcha(HttpServletRequest httpServletRequest, @RequestBody ApiKeyRequest newKeyRequest) throws ApiKeyException {
        LOG.debug("Creating new API key secured by captcha...");
        // instead of checking manager credentials we check captcha token, but we do this once we validated the input (checked mandatory fields)
        checkMandatoryFields(newKeyRequest);

        // When no captcha token was supplied return 401
        String captchaToken = getAuthorizationHeader(httpServletRequest, CAPTCHA_PATTERN);
        if (captchaToken == null) {
            throw new CaptchaException(CAPTCHA_MISSING);
        }
        // Captcha verification, when failed return 401
        if (!captchaManager.verifyCaptchaToken(captchaToken)) {
            throw new CaptchaException(CAPTCHA_VERIFICATION_FAILED);
        }
        checkKeyEmailAppNameExist(newKeyRequest.getEmail(), newKeyRequest.getAppName());

        // authenticate manager client to get the access token
        KeycloakAuthenticationToken authenticationToken =
                (KeycloakAuthenticationToken) customKeycloakAuthenticationProvider.authenticate(managerClientId, managerClientSecret);
        if (authenticationToken == null) {
            throw new ForbiddenException();
        }

        return createClient(newKeyRequest, (KeycloakSecurityContext) authenticationToken.getCredentials());
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
    private ResponseEntity<Object>  createClient(ApiKeyRequest apikeyCreate, KeycloakSecurityContext securityContext) throws ApiKeyException {
        LOG.debug("Creating new keycloak client...");
        ApiKeySecret apikey = keycloakManager.createClient(securityContext, apikeyCreate);
        this.apikeyRepo.save(new ApiKey(apikey));
        LOG.debug("API key {} created", apikey.getApikeyId());

        emailService.sendSimpleMessageUsingTemplate(apikey.getEmail(),
                "Your Europeana API keys",
                apikeyCreatedMail,
                apikey.getFirstName(),
                apikey.getLastName(),
                apikey.getApikeyId(),
                apikey.getClientSecret());
        return new ResponseEntity<>(apikey, HttpStatus.CREATED);
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
    public ApiKey read(@PathVariable("id") String id) throws ApiKeyException {
        LOG.debug("Retrieving details for API key {}...", id);

        checkManagerOrOwnerCredentials(id);
        ApiKey key = checkKeyExists(id);

        return key;
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
    @PutMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ApiKey update(@PathVariable("id") String id, @RequestBody ApiKeyRequest apikeyUpdate) throws ApiKeyException {
        LOG.debug("Updating API key {}...", id);
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        checkMandatoryFields(apikeyUpdate);

        ApiKey key = checkKeyExists(id);
        checkKeyDeprecated(key);

        keycloakManager.updateClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), apikeyUpdate, id);
        copyUpdateValues(key, apikeyUpdate);
        this.apikeyRepo.save(key);

        return key;
    }




    /**
     * Disabling/deprecating a given Apikey. This is done by setting the deprecationdate column to the current time; the data
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
    @PutMapping(path = "/{id}/disable")
    public ResponseEntity disable(@PathVariable("id") String id) throws ApiKeyException {
        LOG.debug("Disabling API key {}...", id);

        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        ApiKey apikey = checkKeyExists(id);
        checkKeyDeprecated(apikey);

        if (!isRequestFromKeycloak(kcAuthToken)) {
            keycloakManager.disableClient(id, (KeycloakSecurityContext) kcAuthToken.getCredentials());
        }
        apikey.setDeprecationDate(new DateTime(DateTimeZone.UTC).toDate());
        this.apikeyRepo.save(apikey);
        return new ResponseEntity(HttpStatus.NO_CONTENT);
    }

    /**
     * Re-enables a given invalid Apikey (of which the deprecationdate column has been set to a past time).
     * NOTE that for now the code does not check if the key is really deprecated; it merely executes the update (if any)
     * in such cases.
     *
     * @param   id the apikey to re-enable
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in apikey.java
     *          HTTP 200 upon successful Apikey update
     *          HTTP 400 when a required parameter is missing or has an invalid value
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 if the apikey is not found
     *          HTTP 406 if a response MIME type other than application/JSON was requested
     *          HTTP 415 if the submitted request does not contain a valid JSON body
     */
    @CrossOrigin(maxAge = 600)
    @PutMapping(path = "/{id}/enable")
    public ApiKey enable(@PathVariable("id") String id) throws ApiKeyException {
        LOG.debug("Enabling API key {}...", id);

        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        ApiKey key = checkKeyExists(id);
        if (key.getDeprecationDate() == null) {
            throw new ApiKeyNotDeprecatedException(id);
        }

        if (!isRequestFromKeycloak(kcAuthToken)) {
            // call Keycloak update only when this request does not come from Keycloak
            keycloakManager.enableClient(id, (KeycloakSecurityContext) kcAuthToken.getCredentials());
        }

        // remove deprecationdate: this enables the key again
        key.setDeprecationDate(null);
        this.apikeyRepo.save(key);
        return key;
    }

    private boolean isRequestFromKeycloak(KeycloakAuthenticationToken keycloakAuthenticationToken) {
        return keycloakAuthenticationToken.getAuthorities()
                .stream()
                .anyMatch(grantedAuthority -> "synchronize".equals(grantedAuthority.getAuthority()));
    }


    /**
     * For deleting an apikey based on the key/id itself
     * @param id
     * @return  HTTP 204 upon successful execution
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 when the requested keycloak identifier is not found in the database
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/{id}")
    public ResponseEntity<String> delete(@PathVariable("id") String id) throws ApiKeyException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        ApiKey apikey = this.apikeyRepo.findOne(id);
        if (apikey == null) {
            throw new ApiKeyNotFoundException(id);
        }

        keycloakManager.deleteClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), id);
        return deleteApiKey(apikey.getApikeyId(), kcAuthToken);
    }

    /**
     * This request is for removing the api key completely from the service using the keycloakId.
     * It may be executed only by the privileged client during the synchronization procedure in Keycloak.
     *
     * @param keycloakId api key identifier from Keycloak
     * @return  HTTP 204 upon successful execution
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 when the requested keycloak identifier is not found in the database
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/synchronize/{keycloakid}")
    public ResponseEntity<String> deleteSynchronize(@PathVariable("keycloakid") String keycloakId) throws ForbiddenException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        Optional<ApiKey> optionalApikey = this.apikeyRepo.findByKeycloakId(keycloakId);
        if (optionalApikey.isPresent()) {
            return deleteApiKey(optionalApikey.get().getApikeyId(), kcAuthToken);
        }
        return new ResponseEntity(HttpStatus.NOT_FOUND);
    }

    private ResponseEntity deleteApiKey(String id, KeycloakAuthenticationToken kcAuthenticationToken) {
        LOG.warn("User {} is permanently deleting API key {}...", kcAuthenticationToken.getPrincipal(), id) ;
        this.apikeyRepo.delete(id);
        return new ResponseEntity(HttpStatus.NO_CONTENT);
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
    public ResponseEntity<Object> validate(HttpServletRequest httpServletRequest) throws ApiKeyException {
        // When no apikey was supplied return 400
        String id = getAuthorizationHeader(httpServletRequest, APIKEY_PATTERN);
        if (id == null) {
            throw new MissingKeyException(APIKEY_MISSING);
        }

        LOG.debug("Validating API key {}...", id);
        // retrieve apikey & check if available
        ApiKey apikey = this.apikeyRepo.findOne(id);
        if (null == apikey) {
            String reason = String.format(APIKEY_NOT_REGISTERED, id);
            LOG.debug(reason);
            // TODO make sure returned message is json!
            return new ResponseEntity(reason, HttpStatus.UNAUTHORIZED);
        }

        checkKeyDeprecated(apikey);

        // set activationDate if this wasn't set before
        Date now = new DateTime(DateTimeZone.UTC).toDate();
        if (null == apikey.getActivationDate()) {
            apikey.setActivationDate(now);
        }
        // set lastAccessDate
        apikey.setLastAccessDate(now);
        this.apikeyRepo.save(apikey);

        return new ResponseEntity(HttpStatus.NO_CONTENT);
    }

    private ApiKey copyUpdateValues(ApiKey apikey, ApiKeyRequest keyRequest) {
        if (null != keyRequest.getFirstName()) {
            apikey.setFirstName(keyRequest.getFirstName());
        }
        if (null != keyRequest.getLastName()) {
            apikey.setLastName(keyRequest.getLastName());
        }
        if (null != keyRequest.getEmail()) {
            apikey.setEmail(keyRequest.getEmail());
        }
        if (null != keyRequest.getWebsite()) {
            apikey.setWebsite(keyRequest.getWebsite());
        }
        if (null != keyRequest.getAppName()) {
            apikey.setAppName(keyRequest.getAppName());
        }
        if (null != keyRequest.getCompany()) {
            apikey.setCompany(keyRequest.getCompany());
        }
        if (null != keyRequest.getSector()) {
            apikey.setSector(keyRequest.getSector());
        }
        return apikey;
    }

    private KeycloakAuthenticationToken checkManagerCredentials() throws ForbiddenException {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        if (!keycloakManager.isManagerClientAuthorized(token)) {
            throw new ForbiddenException();
        }
        return token;
    }

    private KeycloakAuthenticationToken checkManagerOrOwnerCredentials(String id) throws ForbiddenException {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        if (!keycloakManager.isManagerClientAuthorized(token) && !keycloakManager.isOwner(id, token)) {
            throw new ForbiddenException();
        }
        return token;
    }

    private void checkMandatoryFields(ApiKeyRequest apikeyUpdate) throws MissingDataException {
        String retval = "Required parameter(s): ";
        ArrayList<String> missingList = new ArrayList<>();
        if (StringUtils.isBlank(apikeyUpdate.getFirstName())) {
            missingList.add("'firstName'");
        }
        if (StringUtils.isBlank(apikeyUpdate.getLastName())) {
            missingList.add("'lastName'");
        }
        if (StringUtils.isBlank(apikeyUpdate.getEmail())) {
            missingList.add("'email'");
        }
        if (StringUtils.isBlank(apikeyUpdate.getAppName())) {
            missingList.add("'appName'");
        }
        if (StringUtils.isBlank(apikeyUpdate.getCompany())){
            missingList.add("'company'");
        }

        if (!missingList.isEmpty()) {
            throw new MissingDataException(MISSING_PARAMETER, retval + missingList + " not provided");
        }
        if (!EmailValidator.getInstance().isValid(apikeyUpdate.getEmail())) {
            throw new MissingDataException(BAD_EMAIL_FORMAT, BAD_EMAIL_FORMAT);
        }
    }

    private ApiKey checkKeyExists(String id) throws ApiKeyNotFoundException {
        ApiKey key = this.apikeyRepo.findOne(id);
        if (key == null) {
            throw new ApiKeyNotFoundException(id);
        }
        return key;
    }

    private void checkKeyDeprecated(ApiKey key) throws ApiKeyDeprecatedException {
        if (key.getDeprecationDate() != null && key.getDeprecationDate().before(new Date())) {
            throw new ApiKeyDeprecatedException(key.getApikeyId());
        }
    }

    private void checkKeyEmailAppNameExist(String email, String appName) throws ApiKeyExistsException {
        List<ApiKey> apiKeyList = this.apikeyRepo.findByEmailAndAppName(email, appName);
        if (apiKeyList.size() > 0) {
            throw new ApiKeyExistsException(email, appName);
        }
    }

}


