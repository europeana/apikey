package eu.europeana.apikey.controller;

import com.fasterxml.jackson.annotation.JsonView;
import eu.europeana.apikey.captcha.CaptchaManager;
import eu.europeana.apikey.domain.ApiKey;
import eu.europeana.apikey.domain.ApiKeyRequest;
import eu.europeana.apikey.domain.ApiKeySecret;
import eu.europeana.apikey.domain.View;
import eu.europeana.apikey.exception.*;
import eu.europeana.apikey.keycloak.CustomKeycloakAuthenticationProvider;
import eu.europeana.apikey.keycloak.KeycloakAuthenticationToken;
import eu.europeana.apikey.keycloak.KeycloakManager;
import eu.europeana.apikey.keycloak.KeycloakSecurityContext;
import eu.europeana.apikey.mail.MailService;
import eu.europeana.apikey.repos.ApiKeyRepo;
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
 * Handles incoming requests for combined Apikeys & Keycloak clients
 * Authentication is done using Keycloak authentication, but additional constraints my be checked (for example if the
 * account is a manager account)
 *
 * Created by luthien on 18/04/2017.
 * Major refactoring by M. Helinski and Patrick Ehlert in September-November 2019
 * Upgraded to java 11 & spring boot 2 by luthien in December 2019
 * Split in ApiKeyController & ApiKeyClientController by luthien, 06/08/20 (see EA-2156)
 */
@RestController
@RequestMapping("/apikeyclient")
public class ApiKeyClientController{

    // keycloakId that indicates that a new keycloak client should be created (as part of old API key migration)
    public static final String TO_MIGRATE_KEYCLOAKID = "to-migrate";

    private static final Logger LOG   = LogManager.getLogger(ApiKeyClientController.class);

    private static final String MISSING_PARAMETER           = "missing parameter";
    private static final String BAD_EMAIL_FORMAT            = "Email is not properly formatted.";
    private static final String APIKEY_NOT_REGISTERED       = "API key %s is not registered";
    private static final String APIKEY_MISSING              = "Correct header syntax 'Authorization: APIKEY <your_key_here>'";
    private static final String APIKEY_PATTERN              = "APIKEY\\s+([^\\s]+)";
    private static final String CAPTCHA_PATTERN             = "Bearer\\s+([^\\s]+)";
    private static final String CAPTCHA_MISSING             = "Missing Captcha token in the header. Correct syntax: Authorization: Bearer CAPTCHA_TOKEN";
    private static final String CAPTCHA_VERIFICATION_FAILED = "Captcha verification failed.";

    private final ApiKeyRepo     apiKeyRepo;
    private final CaptchaManager captchaManager;
    private final CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;
    private final MailService                          emailService;
    private final SimpleMailMessage                    apiKeyCreatedMail;
    private final KeycloakManager                      keycloakManager;


    @Value("${keycloak.manager-client-id}")
    private String managerClientId;

    @Value("${keycloak.manager-client-secret}")
    private String managerClientSecret;

    @Autowired
    public ApiKeyClientController(ApiKeyRepo apiKeyRepo,
                                  CaptchaManager captchaManager,
                                  CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider,
                                  MailService emailService,
                                  SimpleMailMessage apiKeyCreatedMail,
                                  KeycloakManager keycloakManager) {
        this.apiKeyRepo                           = apiKeyRepo;
        this.captchaManager                       = captchaManager;
        this.customKeycloakAuthenticationProvider = customKeycloakAuthenticationProvider;
        this.emailService                         = emailService;
        this.apiKeyCreatedMail                    = apiKeyCreatedMail;
        this.keycloakManager                      = keycloakManager;
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
     * The ApiKey field is generated as a unique and random 'readable' lowercase string 8 to 12 characters long,
     * e.g. 'rhossindri', 'viancones' or 'ebobrent'; the secret key (Keyckoak ID) is generated by Keycloak.
     * Upon successful execution, an email message containing those two fields will be sent to the email address
     * supplied in the request.
     *
     * @param   newKeyRequest requestbody containing supplied values
     *
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     *          HTTP 201 upon successful ApiKey creation
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
     * The ApiKey field is generated as a unique and random 'readable' lowercase string 8 to 12 characters long,
     * e.g. 'rhossindri', 'viancones' or 'ebobrent'; the secret key (Keyckoak ID) is generated by Keycloak.
     * Upon successful execution, an email message containing those two fields will be sent to the email address
     * supplied in the request.
     *
     * This method is protected with a captcha token that must be supplied in the Authorization header.
     *
     * @param   newKeyRequest requestbody containing supplied values
     *
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     *          HTTP 201 upon successful ApiKey creation
     *          HTTP 400 when a required parameter is missing or has an invalid value
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 406 if a response MIME type other than application/JSON was requested
     *          HTTP 415 if the submitted request does not contain a valid JSON body
     *          HTTP 400 if apikey already exist for <email,appName>
     */
    @CrossOrigin(maxAge = 600)
    @PostMapping(path = "/captcha",
                 produces = MediaType.APPLICATION_JSON_VALUE,
                 consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity createCaptcha(HttpServletRequest httpServletRequest,
                                        @RequestBody ApiKeyRequest newKeyRequest) throws ApiKeyException {
        LOG.debug("Creating new API key secured by captcha...");

        // instead of checking manager credentials we check captcha token, but since a captcha can only be used once we should do this after
        // we validated the input
        checkMandatoryFields(newKeyRequest);
        checkKeyEmailAppNameExist(newKeyRequest.getEmail(), newKeyRequest.getAppName());

        // When no captcha token was supplied return 401
        String captchaToken = getAuthorizationHeader(httpServletRequest, CAPTCHA_PATTERN);
        if (captchaToken == null) {
            throw new CaptchaException(CAPTCHA_MISSING);
        }
        // Captcha verification, when failed return 401
        if (!captchaManager.verifyCaptchaToken(captchaToken)) {
            throw new CaptchaException(CAPTCHA_VERIFICATION_FAILED);
        }

        // retrieve access token for the manager client so we can use that the create a new client
        KeycloakAuthenticationToken authenticationToken = (KeycloakAuthenticationToken) customKeycloakAuthenticationProvider
                .authenticate(managerClientId, managerClientSecret);
        if (authenticationToken == null) {
            throw new ForbiddenException();
        }
        return createClient(newKeyRequest, (KeycloakSecurityContext) authenticationToken.getCredentials());
    }

    /**
     * Create an ApiKey and a Keycloak client with the data supplied in the request and the security context.
     * When successful, the ApiKey is persisted in the apikey Postgresql database while the linked Keycloak client is
     * stored by the Keycloak server. ApiKey and Keycloak ID (aka "Secret (key)") are sent to the supplied email
     * address.
     *
     * @param apiKeyCreate details to be used for the created client
     * @param securityContext security context needed for authorization in Keycloak
     * @return response with created ApiKey details
     */
    private ResponseEntity<Object> createClient(ApiKeyRequest apiKeyCreate,
                                                KeycloakSecurityContext securityContext) throws ApiKeyException {
        LOG.debug("Creating new keycloak client...");
        ApiKeySecret apiKey = keycloakManager.createClient(securityContext, apiKeyCreate);
        this.apiKeyRepo.save(new ApiKey(apiKey));
        LOG.debug("API key {} created", apiKey.getApiKey());

        emailService.sendSimpleMessageUsingTemplate(apiKey.getEmail(),
                                                    "Your Europeana API keys",
                                                    apiKeyCreatedMail,
                                                    apiKey.getFirstName(),
                                                    apiKey.getLastName(),
                                                    apiKey.getApiKey(),
                                                    apiKey.getClientSecret());
        return new ResponseEntity<>(apiKey, HttpStatus.CREATED);
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
     * Retrieves the details associated with the registration of a given ApiKey
     *
     * @param   id string identifying the ApiKey's "public key"
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     *          HTTP 200 upon successful execution
     *          HTTP 401 When reqested api key does not belong to the authenticated client or this client is not a manager client
     *          HTTP 404 when the requested ApiKey is not found in the database
     *          HTTP 406 if a MIME type other than application/JSON was requested
     */
    @CrossOrigin(maxAge = 600)
    @JsonView(View.Public.class)
    @GetMapping(path = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiKey read(@PathVariable("id") String id) throws ApiKeyException {
        LOG.debug("Retrieving details for API key {}...", id);
        checkManagerOrOwnerCredentials(id);
        return checkKeyExists(id);
    }

    /**
     * Changes the registration details of an existing API key for the following public and non-generated values when
     * supplied in the JSON request body:
     *
     * - firstName
     * - lastName
     * - email
     * - company
     * - appName
     * - sector
     *
     * @param   id string identifying the ApiKey's "public key"
     * @param   apiKeyUpdate RequestBody containing supplied values
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     *          HTTP 200 upon successful ApiKey update
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
    public ApiKey update(@PathVariable("id") String id, @RequestBody ApiKeyRequest apiKeyUpdate) throws
                                                                                                 ApiKeyException {
        LOG.debug("Updating API key {}...", id);
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        checkMandatoryFields(apiKeyUpdate);

        ApiKey key = checkKeyExists(id);
        checkKeyDeprecated(key);

        keycloakManager.updateClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), apiKeyUpdate, id);
        copyValuesToApiKey(key, apiKeyUpdate);
        this.apiKeyRepo.save(key);

        return key;
    }

    /**
     * Disables / deprecates a given ApiKey. This is achieved by:
     * - setting the deprecationdate column of the given key to the current time;
     * - disabling the linked Keycloak client
     * Note that this method does not delete any data !
     *
     * @param   id string identifying the ApiKey's "public key"
     * @return  HTTP 204 upon successful execution
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 when the requested ApiKey is not found in the database
     *          HTTP 410 when the requested ApiKey is deprecated (i.e. has a past deprecationdate)
     *
     * Addionally, the field 'ApiKey-not-found' containing the string "apikey-not-found" will be available in the
     * response header to help telling this HTTP 404 apart from one returned by the webserver for other reasons
     */
    @CrossOrigin(maxAge = 600)
    @PutMapping(path = "/{id}/disable")
    public ResponseEntity disable(@PathVariable("id") String id) throws ApiKeyException {
        LOG.debug("Disabling API key {}...", id);

        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        ApiKey                      apiKey      = checkKeyExists(id);
        checkKeyDeprecated(apiKey);

        if (!isRequestFromKeycloak(kcAuthToken)) {
            keycloakManager.disableClient(id, (KeycloakSecurityContext) kcAuthToken.getCredentials());
        }
        apiKey.setDeprecationDate(new DateTime(DateTimeZone.UTC).toDate());
        this.apiKeyRepo.save(apiKey);
        return new ResponseEntity(HttpStatus.NO_CONTENT);
    }

    /**
     * Re-enables a given invalid ApiKey (of which the deprecationdate column has previously been set to a past time).
     * This is achieved by:
     * - removing the contents of the deprecationdate column for this ApiKey; and
     * - enabling the linked Keycloak client
     * The code will execute regardless if the key is actually deprecated or not.
     *
     * @param   id string identifying the ApiKey's "public key"
     * @return  JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     *          HTTP 200 upon successful ApiKey update
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
        ApiKey                      key         = checkKeyExists(id);
        if (key.getDeprecationDate() == null) {
            throw new ApiKeyNotDeprecatedException(id);
        }

        if (!isRequestFromKeycloak(kcAuthToken)) {
            // call Keycloak update only when this request does not come from Keycloak
            keycloakManager.enableClient(id, (KeycloakSecurityContext) kcAuthToken.getCredentials());
        }

        // remove deprecationdate: this enables the key again
        key.setDeprecationDate(null);
        this.apiKeyRepo.save(key);
        return key;
    }

    private boolean isRequestFromKeycloak(KeycloakAuthenticationToken keycloakAuthenticationToken) {
        return keycloakAuthenticationToken.getAuthorities()
                                          .stream()
                                          .anyMatch(grantedAuthority -> "synchronize".equals(grantedAuthority.getAuthority()));
    }

    /**
     * This method deletes BOTH the apikey identified by the supplied string AND the linked Keycloak client.
     * NOTE: this actually deletes the apikey row from the database AND the linked Keycloak client, as opposed to
     * disabling them!
     *
     * @param id string identifying the ApiKey's "public key"
     * @return  HTTP 204 upon successful execution
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 when the requested keycloak identifier is not found in the database
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/{id}")
    public ResponseEntity delete(@PathVariable("id") String id) throws ApiKeyException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        Optional<ApiKey> optionalApiKey = apiKeyRepo.findById(id);

        if (optionalApiKey.isEmpty()) {
            throw new ApiKeyNotFoundException(id);
        }

        keycloakManager.deleteClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), id);
        return deleteApiKey(optionalApiKey.get(), kcAuthToken);
    }

    /**
     * This method deletes ONLY the apikey identified by the linked Keycloak client ID aka "secret key".
     * NOTE: this actually deletes the apikey row in the database, as opposed to disabling the apikey.
     * This method may be executed only by the privileged client during the synchronization procedure in Keycloak.
     *
     * @param keycloakId Keycloak ID aka "secret key"
     * @return  HTTP 204 upon successful execution
     *          HTTP 401 in case of an invalid request
     *          HTTP 403 if the request is unauthorised
     *          HTTP 404 when the requested keycloak identifier is not found in the database
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/synchronize/{keycloakid}")
    public ResponseEntity deleteSynchronize(@PathVariable("keycloakid") String keycloakId) throws ForbiddenException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        Optional<ApiKey> optionalApiKey = this.apiKeyRepo.findByKeycloakId(keycloakId);
        return optionalApiKey.map(value -> deleteApiKey(value, kcAuthToken))
                             .orElseGet(() -> new ResponseEntity(HttpStatus.NOT_FOUND));
    }

    private ResponseEntity deleteApiKey(ApiKey apiKey, KeycloakAuthenticationToken kcAuthenticationToken) {
        LOG.warn("User {} is permanently deleting API key {}...", kcAuthenticationToken.getPrincipal(), apiKey.getApiKey()) ;
        this.apiKeyRepo.delete(apiKey);
        return new ResponseEntity(HttpStatus.NO_CONTENT);
    }

    /**
     * This method can be called by a system administrator to automatically create clients in Keycloak for all
     * API keys that do not have a Keycloak client yet. This will be used during the migration from the old apikey
     * database to a new one with Keycloak as backend.
     */
    @PostMapping(path="/synchronize/missingClient/all")
    public ResponseEntity synchronizeAllMissingClients() throws ApiKeyException{
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        List<ApiKey> keysToUpdate = apiKeyRepo.findAllKeysToMigrate();
        LOG.info("Found {} API keys that have no keycloakId", keysToUpdate.size());

        // TODO check what happens when token expires!? Probably an error occurs and we can resume by calling this again?
        for (ApiKey keyToUpdate : keysToUpdate) {
            synchronizeMissingClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), keyToUpdate.getApiKey());
        }
        LOG.info("Finished creating clients for API keys with missing keycloakId");
        return new ResponseEntity(HttpStatus.NO_CONTENT);
    }

    /**
     * This method can be called by a system administrator to automatically create a client in Keycloak for the
     * provided API key.
     * WARNING: this will replace the existing client secret with a new one!
     */
    @PostMapping(path="/synchronize/missingClient/{apiKey}")
    public ResponseEntity synchronizeMissingClient(@PathVariable String apiKey) throws ApiKeyException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        return synchronizeMissingClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), apiKey);
    }

    private ResponseEntity synchronizeMissingClient(KeycloakSecurityContext securityContext, String apiKey) throws ApiKeyException {
        ApiKey apiClient = checkKeyExists(apiKey);
        LOG.debug("Verified that API key {} exists in database!", apiKey);

        // we only allow apikeys that do not have a keycloakId or one that is set to 'to-migrate'
        if (StringUtils.isNotBlank(apiClient.getKeycloakId()) && !TO_MIGRATE_KEYCLOAKID.equals(apiClient.getKeycloakId())) {
            throw new KCIdNotEmptyException(apiKey, apiClient.getKeycloakId());
        }

        ApiKeyRequest requestClient = copyValuesToNewApiKeyRequest(apiClient);
        String keycloakId = keycloakManager.recreateClient(securityContext, apiKey, requestClient);
        LOG.debug("API key {} has a new keycloak client with id {}", apiKey, keycloakId);

        // update only keycloakId (and keep old registration, activation and deprecated dates!)
        apiClient.setKeycloakId(keycloakId);
        apiKeyRepo.save(apiClient);
        LOG.info("API key {} was updated, keycloakId is {}", apiKey, apiClient.getKeycloakId());
        return new ResponseEntity(HttpStatus.CREATED);
    }



    /**
     * Validates a given ApiKey. Sets last access date and activation date (if not set, ie. first access) with the
     * current date and +1 increments the usage count of this ApiKey.
     *
     * @param   httpServletRequest     request
     *
     * @return  HTTP 204 upon successful validation
     *          HTTP 400 bad request when header does not contain api key
     *          HTTP 401 in case of an unregistered api key
     *          HTTP 410 when the requested ApiKey is deprecated (i.e. has a past deprecationdate)
     */
    @PostMapping(path = "/validate")
    public ResponseEntity validate(HttpServletRequest httpServletRequest) throws ApiKeyException {

        // When no apikey was supplied return 400
        String id = getAuthorizationHeader(httpServletRequest, APIKEY_PATTERN);
        if (StringUtils.isBlank(id)) {
            throw new MissingKeyException(APIKEY_MISSING);
        }
        LOG.debug("Validating API key {}...", id);

        // retrieve apikey & check if available
        Optional<ApiKey> optionalApiKey = apiKeyRepo.findById(id);

        if (optionalApiKey.isEmpty()) {
            String reason = String.format(APIKEY_NOT_REGISTERED, id);
            LOG.debug(reason);
            // TODO make sure returned message is json!
            return new ResponseEntity(reason, HttpStatus.UNAUTHORIZED);
        }

        checkKeyDeprecated(optionalApiKey.get());

        // set activationDate if this wasn't set before
        Date now = new DateTime(DateTimeZone.UTC).toDate();
        if (null == optionalApiKey.get().getActivationDate()) {
            optionalApiKey.get().setActivationDate(now);
        }

        // set lastAccessDate
        optionalApiKey.get().setLastAccessDate(now);
        this.apiKeyRepo.save(optionalApiKey.get());
        return new ResponseEntity(HttpStatus.NO_CONTENT);
    }

    private void copyValuesToApiKey(ApiKey apiKey, ApiKeyRequest keyRequest) {
        if (null != keyRequest.getFirstName()) {
            apiKey.setFirstName(keyRequest.getFirstName());
        }
        if (null != keyRequest.getLastName()) {
            apiKey.setLastName(keyRequest.getLastName());
        }
        if (null != keyRequest.getEmail()) {
            apiKey.setEmail(keyRequest.getEmail());
        }
        if (null != keyRequest.getWebsite()) {
            apiKey.setWebsite(keyRequest.getWebsite());
        }
        if (null != keyRequest.getAppName()) {
            apiKey.setAppName(keyRequest.getAppName());
        }
        if (null != keyRequest.getCompany()) {
            apiKey.setCompany(keyRequest.getCompany());
        }
        if (null != keyRequest.getSector()) {
            apiKey.setSector(keyRequest.getSector());
        }
    }

    /**
     * When we want to create a new Keycloak client (as part of missing-client-synchronization) we need to copy the
     * existing apiKey values to an ApiKeyRequest because this is what KeyCloakManager expects
     * @param apiKey apikey client that is copied
     */
    private ApiKeyRequest copyValuesToNewApiKeyRequest(ApiKey apiKey) {
        return new ApiKeyRequest(
                // make sure required fields are not null
                (StringUtils.isBlank(apiKey.getFirstName()) ? "" : apiKey.getFirstName()),
                (StringUtils.isBlank(apiKey.getLastName()) ? "" : apiKey.getLastName()),
                (StringUtils.isBlank(apiKey.getEmail()) ? "" : apiKey.getEmail()),
                (StringUtils.isBlank(apiKey.getAppName()) ? "" : apiKey.getAppName()),
                (StringUtils.isBlank(apiKey.getCompany()) ? "" : apiKey.getCompany()),
                // set optional fields to null if empty
                (StringUtils.isBlank(apiKey.getSector()) ? null : apiKey.getSector()),
                (StringUtils.isBlank(apiKey.getWebsite()) ? null : apiKey.getWebsite())
        );
    }

    private KeycloakAuthenticationToken checkManagerCredentials() throws ForbiddenException {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) SecurityContextHolder.getContext()
                                                                                               .getAuthentication();
        if (!keycloakManager.isManagerClientAuthorized(token)) {
            throw new ForbiddenException();
        }
        return token;
    }

    private void checkManagerOrOwnerCredentials(String id) throws ForbiddenException {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) SecurityContextHolder.getContext()
                                                                                               .getAuthentication();
        if (!keycloakManager.isManagerClientAuthorized(token) && !keycloakManager.isOwner(id, token)) {
            throw new ForbiddenException();
        }
    }

    private void checkMandatoryFields(ApiKeyRequest apiKeyUpdate) throws MissingDataException {
        String            retval      = "Required parameter(s): ";
        ArrayList<String> missingList = new ArrayList<>();
        if (StringUtils.isBlank(apiKeyUpdate.getFirstName())) {
            missingList.add("'firstName'");
        }
        if (StringUtils.isBlank(apiKeyUpdate.getLastName())) {
            missingList.add("'lastName'");
        }
        if (StringUtils.isBlank(apiKeyUpdate.getEmail())) {
            missingList.add("'email'");
        }
        if (StringUtils.isBlank(apiKeyUpdate.getAppName())) {
            missingList.add("'appName'");
        }
        if (StringUtils.isBlank(apiKeyUpdate.getCompany())) {
            missingList.add("'company'");
        }

        if (!missingList.isEmpty()) {
            throw new MissingDataException(MISSING_PARAMETER, retval + missingList + " not provided");
        }
        if (!EmailValidator.getInstance().isValid(apiKeyUpdate.getEmail())) {
            throw new MissingDataException(BAD_EMAIL_FORMAT, BAD_EMAIL_FORMAT);
        }
    }

    private ApiKey checkKeyExists(String id) throws ApiKeyNotFoundException {
        Optional<ApiKey> optionalApiKey = apiKeyRepo.findById(id);
        if (optionalApiKey.isEmpty()) {
            throw new ApiKeyNotFoundException(id);
        }
        return optionalApiKey.get();
    }

    private void checkKeyDeprecated(ApiKey key) throws ApiKeyDeprecatedException {
        if (key.getDeprecationDate() != null && key.getDeprecationDate().before(new Date())) {
            throw new ApiKeyDeprecatedException(key.getApiKey());
        }
    }

    private void checkKeyEmailAppNameExist(String email, String appName) throws ApiKeyExistsException {
        List<ApiKey> apiKeyList = this.apiKeyRepo.findByEmailAndAppName(email, appName);
        if (!apiKeyList.isEmpty()) {
            throw new ApiKeyExistsException(email, appName);
        }
    }

}


