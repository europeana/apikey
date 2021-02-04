package eu.europeana.apikey.controller;

import com.fasterxml.jackson.annotation.JsonView;
import eu.europeana.api.commons.error.EuropeanaApiException;
import eu.europeana.apikey.captcha.CaptchaManager;
import eu.europeana.apikey.domain.ApiKey;
import eu.europeana.apikey.domain.ApiKeyRequest;
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

import static eu.europeana.apikey.config.ApikeyDefinitions.*;

/**
 * Handles incoming requests for Apikeys that aren't coupled with a Keycloak client
 * Authentication is done using Keycloak authentication, but additional constraints my be checked (for example if the
 * account is a manager account).
 * <p>
 * Created by luthien on 18/04/2017.
 * Major refactoring by M. Helinski and Patrick Ehlert in September-November 2019
 * Upgraded to java 11 & spring boot 2 by luthien in December 2019
 * Another major refactoring to remove automatic link between apikey & client and add support to delete Keycloak
 * users - autumn 2020 (see EA-2156, EA-2234)
 */
@RestController
@RequestMapping("/apikey")
public class ApiKeyController {

    private static final Logger LOG = LogManager.getLogger(ApiKeyController.class);

    private final ApiKeyRepo                           apiKeyRepo;
    private final CaptchaManager                       captchaManager;
    private final CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;
    private final KeycloakClientManager                keycloakClientManager;


    @Autowired
    private MailService emailService;

    @Value("${keycloak.manager-client-id}")
    private String managerClientId;

    @Value("${keycloak.manager-client-secret}")
    private String managerClientSecret;

    @Autowired
    @Qualifier("apikeyTemplate")
    private SimpleMailMessage apiKeyCreatedMsg;

    @Autowired
    @Qualifier("apikeyAndClientTemplate")
    private SimpleMailMessage apiKeyAndClientCreatedMsg;

    @Autowired
    @Qualifier("clientTemplate")
    private SimpleMailMessage clientAddedMsg;

    @Autowired
    public ApiKeyController(ApiKeyRepo apiKeyRepo,
                            CaptchaManager captchaManager,
                            CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider,
                            KeycloakClientManager keycloakClientManager) {
        this.apiKeyRepo = apiKeyRepo;
        this.captchaManager = captchaManager;
        this.customKeycloakAuthenticationProvider = customKeycloakAuthenticationProvider;
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
     * The ApiKey field is generated as a unique and random 'readable' lowercase string 8 to 12 characters long,
     * e.g. 'rhossindri', 'viancones' or 'ebobrent' and is checked for uniqueness against the registered ApiKeys values
     * in the Apikey table.
     * <p>
     * If creating the Apikey is successful, an email containing the Apikey is sent to the email address supplied
     * in this request.
     * <p>
     * Note that this method does not create a Keycloak client.
     * <p>
     *
     * @param newKeyRequest requestbody containing supplied values
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     * HTTP 201 upon successful ApiKey creation
     * HTTP 400 when a required parameter is missing / invalid OR if an apikey already exist for <email,appName>
     * HTTP 401 in case of an unauthorised request
     * HTTP 403 if the requested resource is forbidden
     * HTTP 406 if a response MIME type other than application/JSON was requested in the Accept header
     * HTTP 415 if the submitted request does not contain a valid JSON body
     */
    @CrossOrigin(maxAge = 600)
    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createKey(@RequestBody ApiKeyRequest newKeyRequest) throws EuropeanaApiException {
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
     * The ApiKey field is generated as a unique and random 'readable' lowercase string 8 to 12 characters long,
     * e.g. 'rhossindri', 'viancones' or 'ebobrent' and is checked for uniqueness against the registered ApiKeys values
     * in the Apikey table.
     * <p>
     * If creating the Apikey is successful, an email containing the Apikey is sent to the email address supplied
     * in this request.
     * <p>
     * This method is protected with a captcha token, that must be supplied in the Authorization header.
     * Note that this method does not create a Keycloak client.
     * <p>
     *
     * @param newKeyRequest requestbody containing supplied values
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     * HTTP 201 upon successful ApiKey creation
     * HTTP 400 when a required parameter is missing / invalid OR if an apikey already exist for <email,appName>
     * HTTP 401 in case of an unauthorised request
     * HTTP 403 if the requested resource is forbidden
     * HTTP 406 if a response MIME type other than application/JSON was requested in the Accept header
     * HTTP 415 if the submitted request does not contain a valid JSON body
     */
    @CrossOrigin(maxAge = 600)
    @PostMapping(path = "/captcha",
                 produces = MediaType.APPLICATION_JSON_VALUE,
                 consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createCaptcha(HttpServletRequest httpServletRequest,
                                                @RequestBody ApiKeyRequest newKeyRequest) throws EuropeanaApiException {
        LOG.debug("Creating new API key secured by captcha...");

        // instead of checking manager credentials we check captcha token, but since a captcha can only be used once we
        // should do this after we validated the newKeyRequest
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
     * e.g. 'rhossindri', 'viancones' or 'ebobrent' and is checked for uniqueness against the registered ApiKeys values
     * in the Apikey table.
     * <p>
     * The Keycloak Client will be linked to this Apikey in the following way (referring to database columns):
     * - the Client's 'client_id' column matches the Apikey's 'apikey' column
     * - the Client's 'id' column matches the Apikey's 'keycloakid' column
     * <p>
     * Keycloak generates a Client secret (password) to be used together with the Apikey.
     * If creating the Apikey and Client is successful, an email containing the Apikey and Client secret is sent to
     * the email address supplied in this request.
     * <p>
     *
     * HTTP 201 upon successful ApiKey creation
     * HTTP 400 when a required parameter is missing / invalid OR if an apikey already exist for <email,appName>
     * HTTP 401 in case of an unauthorised request
     * HTTP 403 if the requested resource is forbidden
     * HTTP 406 if a response MIME type other than application/JSON was requested in the Accept header
     * HTTP 415 if the submitted request does not contain a valid JSON body
     *
     * @param newKeyRequest requestbody containing supplied values
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     */
    @CrossOrigin(maxAge = 600)
    @PostMapping(path = "/keycloak",
                 produces = MediaType.APPLICATION_JSON_VALUE,
                 consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createKeyAndClient(@RequestBody ApiKeyRequest newKeyRequest) throws EuropeanaApiException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        LOG.debug("User {} creates new combined API key / KeyCloak Client pair ...", kcAuthToken.getPrincipal());
        checkMandatoryFields(newKeyRequest);
        checkKeyEmailAppNameExist(newKeyRequest.getEmail(), newKeyRequest.getAppName());

        // create new apikey, making sure it is unique
        ApiKey newKey = prepareNewApiKey(newKeyRequest);
        LOG.debug("New Apikey '{}' prepared; creating Client and retrieving its ID ...", newKey.getApiKey());

        KeycloakSecurityContext securityContext = (KeycloakSecurityContext) kcAuthToken.getCredentials();
        ClientRepresentation    newClientRep    = keycloakClientManager.createClient(securityContext, newKey);
        newKey.setKeycloakId(newClientRep.getId());
        LOG.debug("New Client with ID '{}' created linked to Apikey '{}'", newClientRep.getId(), newKey.getApiKey());

        this.apiKeyRepo.save(newKey);
        LOG.debug("Apikey '{}' created", newKey.getApiKey());

        apiKeyAndClientCreatedMsg.setTo(newKey.getEmail());
        emailService.sendApiKeyAndClientEmail(apiKeyAndClientCreatedMsg,
                                              newKey.getFirstName(),
                                              newKey.getLastName(),
                                              newKey.getApiKey(),
                                              newClientRep.getSecret());
        return new ResponseEntity<>(newKey, HttpStatus.CREATED);
    }

    /**
     * Create a Keycloak client linked to the supplied Apikey.
     * When successful, a Keycloak client linked to the Apikey will be present on the Keycloak server.
     * <p>
     * This Keycloak Client will be linked to the supplied Apikey in the following way (referring to database columns):
     * - the Client's 'client_id' column matches the Apikey's 'apikey' column
     * - the Client's 'id' column matches the Apikey's 'keycloakid' column
     * <p>
     * Keycloak generates a Client secret (password) to be used together with the Apikey.
     * If creating the Client is successful, an email containing the Client secret is sent to the email address
     * supplied in this request.
     * <p>
     *
     * TODO check error responses
     *
     * HTTP 201 upon successful Client creation
     * HTTP 400 when a required parameter is missing / invalid OR if an apikey already exist for <email,appName>
     * HTTP 401 in case of an unauthorised request
     * HTTP 403 if the requested resource is forbidden
     * HTTP 406 if a response MIME type other than application/JSON was requested in the Accept header
     * HTTP 415 if the submitted request does not contain a valid JSON body
     *
     * @param apiKey apikey for which the client should be created
     * @return response with created ApiKey details
     * HTTP 201 upon successful ApiKey creation
     */
    @PostMapping(path = "/keycloak/{apiKey}")
    public ResponseEntity<HttpStatus> addClient(@PathVariable String apiKey) throws EuropeanaApiException {
        KeycloakAuthenticationToken kcAuthToken    = checkManagerCredentials();
        ApiKey                      existingApiKey = checkKeyExists(apiKey);
        LOG.debug("Verified that API key {} exists in database!", apiKey);

        // Do not create a Client for an Apikey that already has one (== has a keycloakId set)
        if (StringUtils.isNotBlank(existingApiKey.getKeycloakId())) {
            LOG.error("There is already a Keycloak ID value assigned to Apikey {}", apiKey);
            throw new KCIdNotEmptyException(apiKey, existingApiKey.getKeycloakId());
        }

        KeycloakSecurityContext securityContext = (KeycloakSecurityContext) kcAuthToken.getCredentials();
        ClientRepresentation    newClientRep    = keycloakClientManager.createClient(securityContext, existingApiKey);

        String keycloakId = newClientRep.getId();
        LOG.debug("A Keycloak Client with id {} linked to Apikey {} has been created", keycloakId, apiKey);

        // update only keycloakId (and keep old registration, activation and deprecated dates!)
        existingApiKey.setKeycloakId(keycloakId);
        apiKeyRepo.save(existingApiKey);
        clientAddedMsg.setTo(existingApiKey.getEmail());
        emailService.sendApiKeyAndClientEmail(clientAddedMsg,
                                              existingApiKey.getFirstName(),
                                              existingApiKey.getLastName(),
                                              existingApiKey.getApiKey(),
                                              newClientRep.getSecret());

        LOG.info("API key {} was updated, keycloakId is {}", apiKey, existingApiKey.getKeycloakId());
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    private ResponseEntity<Object> createApikey(ApiKeyRequest newKeyRequest) throws EuropeanaApiException {
        ApiKey newKey = prepareNewApiKey(newKeyRequest);
        this.apiKeyRepo.save(newKey);
        LOG.debug("New Apikey {} created", newKey.getApiKey());
        apiKeyCreatedMsg.setTo(newKey.getEmail());
        emailService.sendApiKeyEmail(apiKeyCreatedMsg, newKey.getFirstName(), newKey.getLastName(), newKey.getApiKey());
        return new ResponseEntity<>(newKey, HttpStatus.CREATED);
    }

    private ApiKey prepareNewApiKey(ApiKeyRequest newKeyRequest) {
        String newPublicKey = generatePublicKey();
        ApiKey newKey = new ApiKey(newPublicKey,
                                   newKeyRequest.getFirstName(),
                                   newKeyRequest.getLastName(),
                                   newKeyRequest.getEmail(),
                                   newKeyRequest.getAppName(),
                                   newKeyRequest.getCompany());
        if (StringUtils.isNotEmpty(newKeyRequest.getWebsite())) {
            newKey.setWebsite(newKeyRequest.getWebsite());
        }
        if (StringUtils.isNotEmpty(newKeyRequest.getSector())) {
            newKey.setSector(newKeyRequest.getSector());
        }
        return newKey;
    }


    /**
     * Get value from the Authorization header of the given request based on the supplied pattern.
     * <p>
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
     * <p>
     * Return statuses:
     * HTTP 200 upon successful execution
     * HTTP 401 When requested api key does not belong to the authenticated client or this client is not a manager client
     * HTTP 404 when the requested ApiKey is not found in the database
     * HTTP 406 if a response MIME type other than application/JSON was requested in the Accept header
     * <p>
     * @param apiKey string identifying the Apikey
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     */
    @CrossOrigin(maxAge = 600)
    @JsonView(View.Public.class)
    @GetMapping(path = "/{apikey}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiKey read(@PathVariable("apikey") String apiKey) throws EuropeanaApiException {
        LOG.debug("Retrieving details for API key '{}' ...", apiKey);
        checkManagerOrOwnerCredentials(apiKey);
        return checkKeyExists(apiKey);
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
     * If this method finds a linked Keycloak Client, it also updates that!
     *
     * Return statuses:
     * HTTP 200 upon successful ApiKey update
     * HTTP 400 when a required parameter is missing
     * HTTP 401 in case of an unauthorised request (or client credential authentication fails)
     * HTTP 403 if the requested resource is forbidden
     * HTTP 404 if the apikey is not found
     * HTTP 406 if a response MIME type other than application/JSON was requested in the Accept header
     * HTTP 410 if the apikey is invalidated / deprecated
     * HTTP 415 if the submitted request does not contain a valid JSON body
     *
     * @param apiKey string identifying the Apikey
     * @param updateKeyRequest RequestBody containing supplied values
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     */
    @CrossOrigin(maxAge = 600)
    @PutMapping(value = "/{apikey}",
                produces = MediaType.APPLICATION_JSON_VALUE,
                consumes = MediaType.APPLICATION_JSON_VALUE)
    public ApiKey update(@PathVariable("apikey") String apiKey, @RequestBody ApiKeyRequest updateKeyRequest) throws
                                                                                                   EuropeanaApiException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();
        checkMandatoryFields(updateKeyRequest);
        ApiKey key = checkKeyExists(apiKey);
        checkKeyDeprecated(key);
        copyValuesToApiKey(key, updateKeyRequest);
        this.apiKeyRepo.save(key);

        String keyCloakId = keycloakClientManager.checkifClientExists(apiKey,
                                                                      (KeycloakSecurityContext) kcAuthToken.getCredentials());
        if (StringUtils.isNotBlank(keyCloakId)) {
            // there is a client in Keycloak with clientId == apiKey; also try and update Client
            keycloakClientManager.updateClient((KeycloakSecurityContext) kcAuthToken.getCredentials(),
                                               updateKeyRequest,
                                               apiKey);
            LOG.debug("User {} has updated Apikey '{}' and linked Client '{}'",
                      kcAuthToken.getPrincipal(),
                      apiKey,
                      keyCloakId);
        } else {
            LOG.debug("User {} has updated API key '{}'", kcAuthToken.getPrincipal(), apiKey);
        }
        return key;
    }

    /**
     * Disables / deprecates a given ApiKey. This is achieved by setting the deprecation date column of the given key
     * to the current time. If this method finds a linked Keycloak Client, it also disables that.
     * No data are deleted by this method.
     * <p>
     * Return statuses:
     *
     * HTTP 401 in case of an unauthorised request
     * HTTP 403 if the requested resource is forbidden
     * HTTP 404 if the apikey is not found
     * HTTP 410 when the requested ApiKey is already deprecated (i.e. has a past deprecationdate)
     * <p>
     * Addionally, the field 'ApiKey-not-found' containing the string "apikey-not-found" will be available in the
     * response header to help telling this HTTP 404 apart from one returned by the webserver for other reasons
     *
     * @param apiKey string identifying the Apikey
     * @return HTTP 204 upon successful execution
     */
    @CrossOrigin(maxAge = 600)
    @PutMapping(path = "/{apikey}/disable")
    public ResponseEntity<Object> disable(@PathVariable("apikey") String apiKey) throws EuropeanaApiException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        ApiKey key = checkKeyExists(apiKey);
        checkKeyDeprecated(key);
        key.setDeprecationDate(new DateTime(DateTimeZone.UTC).toDate());
        this.apiKeyRepo.save(key);

        String keyCloakId = keycloakClientManager.checkifClientExists(apiKey,
                                                                      (KeycloakSecurityContext) kcAuthToken.getCredentials());
        if (StringUtils.isNotBlank(keyCloakId)) {
            // there is a client in Keycloak with clientId == apiKey; also try and disable Client
            keycloakClientManager.disableClient(apiKey, (KeycloakSecurityContext) kcAuthToken.getCredentials());
            LOG.debug("User {} has disabled Apikey '{}' and linked Client '{}'",
                      kcAuthToken.getPrincipal(),
                      apiKey,
                      keyCloakId);
        } else {
            LOG.debug("User {} has disabled API key '{}'", kcAuthToken.getPrincipal(), apiKey);
        }
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /**
     * Re-enables a given invalid ApiKey (of which the deprecationdate column has previously been set to a past time).
     * This is achieved by removing the contents of the deprecationdate column for this ApiKey.
     * <p>
     * If this method finds a linked Keycloak Client, it also enables that.
     * No data are deleted by this method.
     * <p>
     * Return statuses:
     *
     * HTTP 200 upon successful ApiKey update
     * HTTP 400 when a required parameter is missing, has an invalid value or when the Apikey is not deprecated
     * HTTP 401 in case of an unauthorised request
     * HTTP 403 if the requested resource is forbidden
     * HTTP 404 if the apikey is not found
     *
     * @param apiKey string identifying the Apikey
     * @return JSON response containing the fields annotated with @JsonView(View.Public.class) in ApiKey.java
     */
    @CrossOrigin(maxAge = 600)
    @PutMapping(path = "/{apikey}/enable")
    public ApiKey enable(@PathVariable("apikey") String apiKey) throws EuropeanaApiException {
        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        ApiKey key = checkKeyExists(apiKey);
        if (key.getDeprecationDate() == null) {
            throw new ApiKeyNotDeprecatedException(apiKey);
        }
        key.setDeprecationDate(null);
        this.apiKeyRepo.save(key);

        String keyCloakId = keycloakClientManager.checkifClientExists(apiKey,
                                                                      (KeycloakSecurityContext) kcAuthToken.getCredentials());
        if (StringUtils.isNotBlank(keyCloakId)) {
            // there is a client in Keycloak with clientId == apiKey; also try and enable Client
            keycloakClientManager.enableClient(apiKey, (KeycloakSecurityContext) kcAuthToken.getCredentials());
            LOG.debug("User {} has enabled Apikey '{}' and linked Client '{}'",
                      kcAuthToken.getPrincipal(),
                      apiKey,
                      keyCloakId);
        } else {
            LOG.debug("User {} has enabled API key '{}'", kcAuthToken.getPrincipal(), apiKey);
        }
        return key;
    }

    /**
     * This method deletes the apikey identified by the supplied string.
     * NOTE: this actually deletes the apikey row from the database, as opposed to disabling it!
     * <p>
     * NOTE: if this method finds a linked Keycloak Client, it also deletes that.
     * <p>
     * Return statuses:
     *
     * HTTP 401 in case of an unauthorised request
     * HTTP 403 if the requested resource is forbidden
     * HTTP 404 when the requested keycloak identifier is not found in the database
     *
     * @param apiKey string identifying the ApiKey's "public key"
     * @return HTTP 204 upon successful execution
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/{apikey}")
    public ResponseEntity<Object> delete(@PathVariable("apikey") String apiKey) throws EuropeanaApiException {

        KeycloakAuthenticationToken kcAuthToken = checkManagerCredentials();

        Optional<ApiKey> optionalApiKey = apiKeyRepo.findById(apiKey);
        LOG.warn("User {} is permanently deleting API key {}...", kcAuthToken.getPrincipal(), apiKey);

        if (optionalApiKey.isEmpty()) {
            throw new ApiKeyNotFoundException(apiKey);
        }
        this.apiKeyRepo.delete(optionalApiKey.get());

        String keyCloakId = keycloakClientManager.checkifClientExists(apiKey,
                                                                      (KeycloakSecurityContext) kcAuthToken.getCredentials());
        if (StringUtils.isNotBlank(keyCloakId)) {
            // there is a client in Keycloak with clientId == apiKey, delete Client as well
            keycloakClientManager.deleteClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), apiKey);
            LOG.debug("User {} has deleted Apikey '{}' and linked Client '{}'",
                      kcAuthToken.getPrincipal(),
                      apiKey,
                      keyCloakId);
        } else {
            LOG.debug("User {} has deleted API key '{}'", kcAuthToken.getPrincipal(), apiKey);
        }
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /**
     * Validates a given ApiKey. Sets last access date and activation date (if not set, ie. first access) with the
     * current date and +1 increments the usage count of this ApiKey.
     * <p>
     * Return statuses:
     *
     * HTTP 400 bad request when header does not contain api key
     * HTTP 401 in case of an unauthorised request (here: if the apikey is not registered)
     * HTTP 410 when the requested ApiKey is deprecated (i.e. has a past deprecationdate)
     *
     * @param httpServletRequest request
     * @return HTTP 204 upon successful validation
     */
    @PostMapping(path = "/validate")
    public ResponseEntity<Object> validate(HttpServletRequest httpServletRequest) throws EuropeanaApiException {

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
            throw new MissingDataException(MISSING_PARAMETER + retval + missingList + " not provided");
        }
        if (!EmailValidator.getInstance().isValid(apiKeyUpdate.getEmail())) {
            throw new MissingDataException(BAD_EMAIL_FORMAT);
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

}


