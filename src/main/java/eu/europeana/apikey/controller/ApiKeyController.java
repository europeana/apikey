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
import eu.europeana.apikey.keycloak.KeycloakClientManager;
import eu.europeana.apikey.keycloak.KeycloakSecurityContext;
import eu.europeana.apikey.mail.MailService;
import eu.europeana.apikey.repos.ApiKeyRepo;
import eu.europeana.apikey.util.PassGenerator;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.keycloak.representations.idm.ClientRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handles incoming requests for Apikeys that aren't coupled with a Keycloak client
 * Authentication is done using Keycloak authentication, but additional constraints my be checked (for example if the
 * account is a manager account).
 * <p>
 * Created by luthien on 18/04/2017.
 * Major refactoring by M. Helinski and Patrick Ehlert in September-November 2019
 * Upgraded to java 11 & spring boot 2 by luthien in December 2019
 * Refactored from the original code by luthien, 06/08/20 (see EA-2156)
 */
@RestController
@RequestMapping("/apikey")
public class ApiKeyController {

    private static final Logger LOG = LogManager.getLogger(ApiKeyController.class);

    private static final String MISSING_PARAMETER           = "missing parameter";
    private static final String BAD_EMAIL_FORMAT            = "Email is not properly formatted.";
    private static final String APIKEY_NOT_REGISTERED       = "API key %s is not registered";
    private static final String APIKEY_MISSING              = "Correct header syntax 'Authorization: APIKEY <your_key_here>'";
    private static final String APIKEY_PATTERN              = "APIKEY\\s+([^\\s]+)";
    private static final String CAPTCHA_PATTERN             = "Bearer\\s+([^\\s]+)";
    private static final String CAPTCHA_MISSING             = "Missing Captcha token in the header. Correct syntax: Authorization: Bearer CAPTCHA_TOKEN";
    private static final String CAPTCHA_VERIFICATION_FAILED = "Captcha verification failed.";

    private final ApiKeyRepo                           apiKeyRepo;
    private final CaptchaManager                       captchaManager;
    private final CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;
    private final MailService                          emailService;
    private final SimpleMailMessage                    apiKeyCreatedMail;
    private final SimpleMailMessage                    apiKeyAndClientCreatedMail;
    private final SimpleMailMessage                    clientAddedMail;
    private final KeycloakClientManager                keycloakClientManager;

    @Value("${keycloak.manager-client-id}")
    private String managerClientId;

    @Value("${keycloak.manager-client-secret}")
    private String managerClientSecret;

    @Autowired
    public ApiKeyController(ApiKeyRepo apiKeyRepo,
                            CaptchaManager captchaManager,
                            CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider,
                            MailService emailService,
                            @Qualifier("apikeyMail") SimpleMailMessage apiKeyCreatedMail,
                            @Qualifier("apikeyAndClientMail") SimpleMailMessage apiKeyAndClientCreatedMail,
                            @Qualifier("clientAddedMail") SimpleMailMessage clientAddedMail,
                            KeycloakClientManager keycloakClientManager) {
        this.apiKeyRepo = apiKeyRepo;
        this.captchaManager = captchaManager;
        this.customKeycloakAuthenticationProvider = customKeycloakAuthenticationProvider;
        this.emailService = emailService;
        this.apiKeyCreatedMail = apiKeyCreatedMail;
        this.apiKeyAndClientCreatedMail = apiKeyAndClientCreatedMail;
        this.clientAddedMail = clientAddedMail;
        this.keycloakClientManager = keycloakClientManager;
    }


    /**
     * Create a new API key with the following mandatory values supplied in a JSON request body:
     * - firstName
     * - lastName
     * - email
     * - appName
     * - company
     * <p>
     * The following fields are optional:
     * - website
     * - sector
     * <p>
     * NOTE that this method does NOT create a Keycloak client!
     * The newly generated public key is checked for uniqueness against the registered ApiKeys values in the Apikey
     * table; not against the registered Keycloak clients.
     * However, because ApiKeys created with a linked Keycloak Client are also registered in the Apikey table, it
     * can be expected that any ApiKey created with this method will also be unique among Keycloak Client ID's.
     * <p>
     * The ApiKey field is generated as a unique and random 'readable' lowercase string 8 to 12 characters long,
     * e.g. 'rhossindri', 'viancones' or 'ebobrent'; the secret key is a random type-4 UUID (similar to the
     * Keycloak Client ID). Upon successful execution, an email message containing those two fields will be sent to
     * the email address supplied in the request.
     *
     * @param newKeyRequest requestbody containing supplied values
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     * HTTP 201 upon successful ApiKey creation
     * HTTP 400 when a required parameter is missing or has an invalid value
     * HTTP 401 in case of an invalid request
     * HTTP 403 if the request is unauthorised
     * HTTP 406 if a response MIME type other than application/JSON was requested
     * HTTP 415 if the submitted request does not contain a valid JSON body
     * HTTP 400 if apikey already exist for <email,appName>
     */
    @CrossOrigin(maxAge = 600)
    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createKey(@RequestBody ApiKeyRequest newKeyRequest) throws ApiKeyException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        LOG.debug("User {} creates new API key ... ", kcAuthToken.getPrincipal());
        checkMandatoryFields(newKeyRequest);
        checkKeyEmailAppNameExist(newKeyRequest.getEmail(), newKeyRequest.getAppName());
        return createApikey(newKeyRequest);
    }

    /**
     * Create a new API key with the following mandatory values supplied in a JSON request body:
     * - firstName
     * - lastName
     * - email
     * - appName
     * - company
     * <p>
     * The following fields are optional:
     * - website
     * - sector
     * <p>
     * NOTE that this method does NOT create a Keycloak client!
     * The newly generated public key is checked for uniqueness against the registered ApiKeys values in the Apikey
     * table; not against the registered Keycloak clients.
     * However, because ApiKeys created with a linked Keycloak Client are also registered in the Apikey table, it
     * can be expected that any ApiKey created with this method will also be unique among Keycloak Client ID's.
     * <p>
     * The ApiKey field is generated as a unique and random 'readable' lowercase string 8 to 12 characters long,
     * e.g. 'rhossindri', 'viancones' or 'ebobrent'; the secret key is a random type-4 UUID (similar to the
     * Keycloak Client ID). Upon successful execution, an email message containing those two fields will be sent to
     * the email address supplied in the request.
     * <p>
     * This method is protected with a captcha token that must be supplied in the Authorization header.
     *
     * @param newKeyRequest requestbody containing supplied values
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     * HTTP 201 upon successful ApiKey creation
     * HTTP 400 when a required parameter is missing or has an invalid value
     * HTTP 401 in case of an invalid request
     * HTTP 403 if the request is unauthorised
     * HTTP 406 if a response MIME type other than application/JSON was requested
     * HTTP 415 if the submitted request does not contain a valid JSON body
     * HTTP 400 if apikey already exist for <email,appName>
     */
    @CrossOrigin(maxAge = 600)
    @PostMapping(path = "/captcha",
                 produces = MediaType.APPLICATION_JSON_VALUE,
                 consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createCaptcha(HttpServletRequest httpServletRequest,
                                                @RequestBody ApiKeyRequest newKeyRequest) throws ApiKeyException {
        LOG.debug("Creating new API key secured by captcha...");

        // instead of checking manager credentials we check captcha token, but since a captcha can only be used once we should do this after
        // we validated the newKeyRequest
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
        KeycloakAuthenticationToken kcAuthToken = (KeycloakAuthenticationToken) customKeycloakAuthenticationProvider.authenticateAdminUser(
                managerClientId,
                managerClientSecret);
        if (kcAuthToken == null) {
            throw new ForbiddenException();
        }
        return createApikey(newKeyRequest);
    }

    private ResponseEntity<Object> createApikey(ApiKeyRequest newKeyRequest) throws ApiKeyException {
        ApiKeySecret newApiKey = prepareNewApiKey(newKeyRequest);
        LOG.debug("New Apikey {} created", newApiKey.getApiKey());
        emailService.sendApiKeyEmail(newApiKey.getEmail(),
                                     "Your Europeana API key",
                                     apiKeyCreatedMail,
                                     newApiKey.getFirstName(),
                                     newApiKey.getLastName(),
                                     newApiKey.getApiKey());
        return new ResponseEntity<>(newApiKey, HttpStatus.CREATED);
    }

    /**
     * Create a new API key / Keycloak Client pair, with the following mandatory values supplied in a JSON request body:
     * - firstName
     * - lastName
     * - email
     * - appName
     * - company
     * <p>
     * The following fields are optional:
     * - website
     * - sector
     * <p>
     * The ApiKey field is generated as a unique and random 'readable' lowercase string 8 to 12 characters long,
     * e.g. 'rhossindri', 'viancones' or 'ebobrent'; the secret key (Keyckoak ID) is generated by Keycloak.
     * Upon successful execution, an email message containing those two fields will be sent to the email address
     * supplied in the request.
     *
     * @param newKeyRequest requestbody containing supplied values
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     * HTTP 201 upon successful ApiKey creation
     * HTTP 400 when a required parameter is missing or has an invalid value
     * HTTP 401 in case of an invalid request
     * HTTP 403 if the request is unauthorised
     * HTTP 406 if a response MIME type other than application/JSON was requested
     * HTTP 415 if the submitted request does not contain a valid JSON body
     * HTTP 400 if apikey already exist for <email,appName>
     */
    @CrossOrigin(maxAge = 600)
    @PostMapping(path = "/keycloak",
                 produces = MediaType.APPLICATION_JSON_VALUE,
                 consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createKeyAndClient(@RequestBody ApiKeyRequest newKeyRequest) throws ApiKeyException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        LOG.debug("User {} creates new combined API key / KeyCloak Client pair ...", kcAuthToken.getPrincipal());
        checkMandatoryFields(newKeyRequest);
        checkKeyEmailAppNameExist(newKeyRequest.getEmail(), newKeyRequest.getAppName());

        // create new apikey, making sure it is unique
        ApiKeySecret newApiKey = prepareNewApiKey(newKeyRequest);
        LOG.debug("New Apikey {} created. Creating Client ...", newApiKey.getApiKey());

        KeycloakSecurityContext securityContext = (KeycloakSecurityContext) kcAuthToken.getCredentials();
        ApiKeyRequest           requestClient   = copyValuesToNewApiKeyRequest(newApiKey);
        ClientRepresentation    newClientRep    = keycloakClientManager.createClient(securityContext,
                                                                                     newApiKey.getApiKey(),
                                                                                     requestClient);
        LOG.debug("New Client {} created.", newClientRep.getId());

        emailService.sendApiKeyAndClientEmail(newApiKey.getEmail(),
                                              "Your Europeana API keys",
                                              apiKeyAndClientCreatedMail,
                                              newApiKey.getFirstName(),
                                              newApiKey.getLastName(),
                                              newApiKey.getApiKey(),
                                              newClientRep.getSecret());
        return new ResponseEntity<>(newApiKey, HttpStatus.CREATED);
    }

    private ApiKeySecret prepareNewApiKey(ApiKeyRequest newKeyRequest) {
        // ApiKey must be unique
        String newPublicKey = generatePublicKey();
        // gather all data to sent back to user (so also secret)
        ApiKeySecret newApiKey = new ApiKeySecret(newPublicKey,
                                                  newKeyRequest.getFirstName(),
                                                  newKeyRequest.getLastName(),
                                                  newKeyRequest.getEmail(),
                                                  newKeyRequest.getAppName(),
                                                  newKeyRequest.getCompany(),
                                                  UUID.randomUUID().toString());
        // set optional fields
        if (StringUtils.isNotEmpty(newKeyRequest.getWebsite())) {
            newApiKey.setWebsite(newKeyRequest.getWebsite());
        }
        if (StringUtils.isNotEmpty(newKeyRequest.getSector())) {
            newApiKey.setSector(newKeyRequest.getSector());
        }

        this.apiKeyRepo.save(new ApiKey(newApiKey));
        LOG.debug("Stand-alone API key with public key {} created", newApiKey.getApiKey());
        return newApiKey;
    }

    /**
     * Create a Keycloak client linked to the Apikey. When successful, a Keycloak client is stored on the Keycloak
     * server, and the Client UUID is returned to be stored in the Apikey table, column KeycloakID.
     * ApiKey and Keycloak ID (the Keycloak identifier of the created Client) are sent to the supplied email address.
     *
     * @param apiKey apikey for which the client should be created
     * @return response with created ApiKey details
     */
    @PostMapping(path = "/keycloak/{apiKey}")
    public ResponseEntity<HttpStatus> addClient(@PathVariable String apiKey) throws ApiKeyException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        ApiKey                      clientKey   = checkKeyExists(apiKey);
        LOG.debug("Verified that API key {} exists in database!", apiKey);

        // Do not create a Client for an Apikey that already has one (== has a keycloakId set)
        if (StringUtils.isNotBlank(clientKey.getKeycloakId())) {
            LOG.error("There is already a Keycloak ID value assigned to Apikey {}", apiKey);
            throw new KCIdNotEmptyException(apiKey, clientKey.getKeycloakId());
        }

        KeycloakSecurityContext securityContext = (KeycloakSecurityContext) kcAuthToken.getCredentials();
        ApiKeyRequest           requestClient   = copyValuesToNewApiKeyRequest(clientKey);
        ClientRepresentation    newClientRep    = keycloakClientManager.createClient(securityContext,
                                                                                     clientKey.getApiKey(),
                                                                                     requestClient);

        String keycloakId = newClientRep.getId();
        LOG.debug("A Keycloak Client with id {} linked to Apikey {} has been created", keycloakId, apiKey);

        // update only keycloakId (and keep old registration, activation and deprecated dates!)
        clientKey.setKeycloakId(keycloakId);
        apiKeyRepo.save(clientKey);

        emailService.sendClientAddedEmail(clientKey.getEmail(),
                                          "Your Europeana API keys",
                                          apiKeyAndClientCreatedMail,
                                          clientKey.getFirstName(),
                                          clientKey.getLastName(),
                                          clientKey.getApiKey(),
                                          newClientRep.getSecret());

        LOG.info("API key {} was updated, keycloakId is {}", apiKey, clientKey.getKeycloakId());
        return new ResponseEntity<>(HttpStatus.CREATED);
    }


    /**
     * Get value from the Authorization header of the given request based on the supplied pattern.
     *
     * @param httpServletRequest request with the header
     * @param valuePattern       pattern of the Authorization header to retrieve the value
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
     * @param id string identifying the ApiKey's "public key"
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     * HTTP 200 upon successful execution
     * HTTP 401 When reqested api key does not belong to the authenticated client or this client is not a manager client
     * HTTP 404 when the requested ApiKey is not found in the database
     * HTTP 406 if a MIME type other than application/JSON was requested
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
     * <p>
     * - firstName
     * - lastName
     * - email
     * - company
     * - appName
     * - sector
     * <p>
     * Note that this method does not update a Keycloak Client!
     *
     * @param apiKey               string identifying the ApiKey's "public key"
     * @param updateKeyRequest RequestBody containing supplied values
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     * HTTP 200 upon successful ApiKey update
     * HTTP 400 when a required parameter is missing
     * HTTP 401 in case of an unauthorized request (client credential authentication fails)
     * HTTP 403 if the request is unauthorised (when the client is not a manager)
     * HTTP 404 if the apikey is not found
     * HTTP 406 if a response MIME type other than application/JSON was requested
     * HTTP 410 if the apikey is invalidated / deprecated
     * HTTP 415 if the submitted request does not contain a valid JSON body
     */
    @CrossOrigin(maxAge = 600)
    @PutMapping(value = "/{apikey}",
                produces = MediaType.APPLICATION_JSON_VALUE,
                consumes = MediaType.APPLICATION_JSON_VALUE)
    public ApiKey update(@PathVariable("apikey") String apiKey, @RequestBody ApiKeyRequest updateKeyRequest) throws
                                                                                                     ApiKeyException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        checkMandatoryFields(updateKeyRequest);

        ApiKey key = checkKeyExists(apiKey);
        checkKeyDeprecated(key);

        copyValuesToApiKey(key, updateKeyRequest);
        this.apiKeyRepo.save(key);
        LOG.debug("User {} has updated API key {}", kcAuthToken.getPrincipal(), apiKey);

        String keyCloakId = keycloakClientManager.checkifClientExists(apiKey,
                                                                      (KeycloakSecurityContext) kcAuthToken.getCredentials());
        if (StringUtils.isNotBlank(keyCloakId)) {
            // there is a client in Keycloak with clientId == apiKey; also try and update Client
            keycloakClientManager.updateClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), updateKeyRequest, apiKey);
            LOG.debug("User {} updated Client {} linked with Apikey {}", kcAuthToken.getPrincipal(), keyCloakId, apiKey);
        }

        return key;
    }

    /**
     * Disables / deprecates a given ApiKey. This is achieved by setting the deprecation date column of the given key
     * to the current time.
     * Note that this method does not disable a Keycloak Client nor delete any data!
     *
     * @param apikey string identifying the ApiKey's "public key"
     * @return HTTP 204 upon successful execution
     * HTTP 401 in case of an invalid request
     * HTTP 403 if the request is unauthorised
     * HTTP 404 when the requested ApiKey is not found in the database
     * HTTP 410 when the requested ApiKey is deprecated (i.e. has a past deprecationdate)
     * <p>
     * Addionally, the field 'ApiKey-not-found' containing the string "apikey-not-found" will be available in the
     * response header to help telling this HTTP 404 apart from one returned by the webserver for other reasons
     */
    @CrossOrigin(maxAge = 600)
    @PutMapping(path = "/{apikey}/disable")
    public ResponseEntity<Object> disable(@PathVariable("apikey") String apiKey) throws ApiKeyException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        ApiKey key = checkKeyExists(apiKey);
        checkKeyDeprecated(key);
        key.setDeprecationDate(new DateTime(DateTimeZone.UTC).toDate());
        this.apiKeyRepo.save(key);
        LOG.debug("User {} has disabled API key {}", kcAuthToken.getPrincipal(), apiKey);

        String keyCloakId = keycloakClientManager.checkifClientExists(apiKey,
                                                                      (KeycloakSecurityContext) kcAuthToken.getCredentials());
        if (StringUtils.isNotBlank(keyCloakId)) {
            // there is a client in Keycloak with clientId == apiKey; also try and disable Client
            keycloakClientManager.disableClient(apiKey, (KeycloakSecurityContext) kcAuthToken.getCredentials());
            LOG.debug("User {} disabled Client {} linked with Apikey {}", kcAuthToken.getPrincipal(), keyCloakId, apiKey);
        }

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /**
     * Re-enables a given invalid ApiKey (of which the deprecationdate column has previously been set to a past time).
     * This is achieved by removing the contents of the deprecationdate column for this ApiKey.
     * The code will execute regardless if the key is actually deprecated or not.
     * NOTE: this method will not try and re-enable a Keycloak Client.
     *
     * @param id string identifying the ApiKey's "public key"
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     * HTTP 200 upon successful ApiKey update
     * HTTP 400 when a required parameter is missing or has an invalid value
     * HTTP 401 in case of an invalid request
     * HTTP 403 if the request is unauthorised
     * HTTP 404 if the apikey is not found
     * HTTP 406 if a response MIME type other than application/JSON was requested
     * HTTP 415 if the submitted request does not contain a valid JSON body
     */
    @CrossOrigin(maxAge = 600)
    @PutMapping(path = "/{apikey}/enable")
    public ApiKey enable(@PathVariable("apikey") String apiKey) throws ApiKeyException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        ApiKey key = checkKeyExists(apiKey);
        if (key.getDeprecationDate() == null) {
            throw new ApiKeyNotDeprecatedException(apiKey);
        }
        key.setDeprecationDate(null);
        this.apiKeyRepo.save(key);
        LOG.debug("User {} has enabled API key {}", kcAuthToken.getPrincipal(), apiKey);

        String keyCloakId = keycloakClientManager.checkifClientExists(apiKey,
                                                                      (KeycloakSecurityContext) kcAuthToken.getCredentials());
        if (StringUtils.isNotBlank(keyCloakId)) {
            // there is a client in Keycloak with clientId == apiKey; also try and enable Client
            keycloakClientManager.disableClient(apiKey, (KeycloakSecurityContext) kcAuthToken.getCredentials());
            LOG.debug("User {} enabled Client {} linked with Apikey {}", kcAuthToken.getPrincipal(), keyCloakId, apiKey);
        }
        return key;
    }

    /**
     * This method deletes the apikey identified by the supplied string.
     * NOTE: this actually deletes the apikey row from the database, as opposed to disabling it!
     * NOTE: this method does NOT delete any Keycloak Clients.
     *
     * @param apikey string identifying the ApiKey's "public key"
     * @return HTTP 204 upon successful execution
     * HTTP 401 in case of an invalid request
     * HTTP 403 if the request is unauthorised
     * HTTP 404 when the requested keycloak identifier is not found in the database
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/{apikey}")
    public ResponseEntity<Object> delete(@PathVariable("apikey") String apiKey) throws ApiKeyException {

        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        Optional<ApiKey> optionalApiKey = apiKeyRepo.findById(apiKey);
        LOG.warn("User {} is permanently deleting API key {}...", kcAuthToken.getPrincipal(), apiKey);

        if (optionalApiKey.isEmpty()) {
            throw new ApiKeyNotFoundException(apiKey);
        }
        this.apiKeyRepo.delete(optionalApiKey.get());
        LOG.debug("User {} has deleted API key {}", kcAuthToken.getPrincipal(), apiKey);

        String keyCloakId = keycloakClientManager.checkifClientExists(apiKey,
                                                                      (KeycloakSecurityContext) kcAuthToken.getCredentials());

        if (StringUtils.isNotBlank(keyCloakId)) {
            // there is a client in Keycloak with clientId == apiKey, delete Client as well
            keycloakClientManager.deleteClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), apiKey);
            LOG.debug("User {} has deleted Client {} linked with Apikey {}", kcAuthToken.getPrincipal(), keyCloakId, apiKey);
        }

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /**
     * Validates a given ApiKey. Sets last access date and activation date (if not set, ie. first access) with the
     * current date and +1 increments the usage count of this ApiKey.
     *
     * @param httpServletRequest request
     * @return HTTP 204 upon successful validation
     * HTTP 400 bad request when header does not contain api key
     * HTTP 401 in case of an unregistered api key
     * HTTP 410 when the requested ApiKey is deprecated (i.e. has a past deprecationdate)
     */
    @PostMapping(path = "/validate")
    public ResponseEntity<Object> validate(HttpServletRequest httpServletRequest) throws ApiKeyException {

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
            return new ResponseEntity<>(reason, HttpStatus.UNAUTHORIZED);
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
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    protected void copyValuesToApiKey(ApiKey apiKey, ApiKeyRequest keyRequest) {
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

    protected KeycloakAuthenticationToken checkManagerCredentials() throws ForbiddenException {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) SecurityContextHolder.getContext()
                                                                                               .getAuthentication();
        if (!keycloakClientManager.isManagerClientAuthorized(token)) {
            throw new ForbiddenException();
        }
        return token;
    }

    protected void checkManagerOrOwnerCredentials(String id) throws ForbiddenException {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) SecurityContextHolder.getContext()
                                                                                               .getAuthentication();
        if (!keycloakClientManager.isManagerClientAuthorized(token) && !keycloakClientManager.isOwner(id, token)) {
            throw new ForbiddenException();
        }
    }

    protected void checkMandatoryFields(ApiKeyRequest apiKeyUpdate) throws MissingDataException {
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

    protected ApiKey checkKeyExists(String id) throws ApiKeyNotFoundException {
        Optional<ApiKey> optionalApiKey = apiKeyRepo.findById(id);
        if (optionalApiKey.isEmpty()) {
            throw new ApiKeyNotFoundException(id);
        }
        return optionalApiKey.get();
    }

    protected void checkKeyDeprecated(ApiKey key) throws ApiKeyDeprecatedException {
        if (key.getDeprecationDate() != null && key.getDeprecationDate().before(new Date())) {
            throw new ApiKeyDeprecatedException(key.getApiKey());
        }
    }

    protected void checkKeyEmailAppNameExist(String email, String appName) throws ApiKeyExistsException {
        List<ApiKey> apiKeyList = this.apiKeyRepo.findByEmailAndAppName(email, appName);
        if (!apiKeyList.isEmpty()) {
            throw new ApiKeyExistsException(email, appName);
        }
    }


    /**
     * Generate a new Apikey (public ID). Note that this method is identical to how an Apikey / Keycloak Client ID is
     * generated except that it does not check against Keycloak for uniqueness, but against the Apikey table.
     *
     * @return newly generated public ApiKey
     */
    private String generatePublicKey() {
        String        id;
        PassGenerator pg = new PassGenerator();
        do {
            id = pg.generate(RandomUtils.nextInt(8, 13));
        } while (apiKeyRepo.findById(id).isPresent());
        return id;
    }

    /**
     * When we want to create a new Keycloak client (as part of missing-client-synchronization) we need to copy the
     * existing apiKey values to an ApiKeyRequest because this is what KeyCloakClientManager expects
     *
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
                (StringUtils.isBlank(apiKey.getWebsite()) ? null : apiKey.getWebsite()));
    }

    /**
     * When we want to create a new Keycloak client (as part of missing-client-synchronization) we need to copy the
     * existing ApiKeySecret values to an ApiKeyRequest because this is what KeyCloakClientManager expects
     *
     * @param apiKeySecret ApiKeySecret containing data to be copied to ApiKeyRequest
     */
    private ApiKeyRequest copyValuesToNewApiKeyRequest(ApiKeySecret apiKeySecret) {
        return new ApiKeyRequest(
                // make sure required fields are not null
                (StringUtils.isBlank(apiKeySecret.getFirstName()) ? "" : apiKeySecret.getFirstName()),
                (StringUtils.isBlank(apiKeySecret.getLastName()) ? "" : apiKeySecret.getLastName()),
                (StringUtils.isBlank(apiKeySecret.getEmail()) ? "" : apiKeySecret.getEmail()),
                (StringUtils.isBlank(apiKeySecret.getAppName()) ? "" : apiKeySecret.getAppName()),
                (StringUtils.isBlank(apiKeySecret.getCompany()) ? "" : apiKeySecret.getCompany()),
                // set optional fields to null if empty
                (StringUtils.isBlank(apiKeySecret.getSector()) ? null : apiKeySecret.getSector()),
                (StringUtils.isBlank(apiKeySecret.getWebsite()) ? null : apiKeySecret.getWebsite()));
    }

}


