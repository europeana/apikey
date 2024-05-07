package eu.europeana.apikey.config;

/**
 * Created by luthien on 10/11/2020.
 */
public class ApikeyDefinitions {

    /**
     * The constant TO_MIGRATE_KEYCLOAKID.
     */
    public static final String TO_MIGRATE_KEYCLOAKID                 = "to-migrate";
    /**
     * The constant MISSING_PARAMETER.
     */
    public static final String MISSING_PARAMETER                     = "Missing parameter. ";
    /**
     * The constant BAD_EMAIL_FORMAT.
     */
    public static final String BAD_EMAIL_FORMAT                      = "Email %s is not properly formatted.";
    /**
     * The constant APIKEY_NOT_REGISTERED.
     */
    public static final String APIKEY_NOT_REGISTERED                 = "API key %s is not registered";
    /**
     * The constant APIKEY_DEPRECATED.
     */
    public static final String APIKEY_DEPRECATED                     = "API key %s is deprecated";
    /**
     * The constant APIKEY_NOT_DEPRECATED.
     */
    public static final String APIKEY_NOT_DEPRECATED                 = "API key %s is not deprecated!";
    /**
     * The constant EMAIL_APPNAME_EXISTS.
     */
    public static final String EMAIL_APPNAME_EXISTS                  = "There already is an API key registered with application name %s and email %s.";
    /**
     * The constant CLIENT_NO_MANAGER.
     */
    public static final String CLIENT_NO_MANAGER                     = "Client %s is not authorised to manage API keys";
    /**
     * The constant APIKEY_MISSING.
     */
    public static final String APIKEY_MISSING                        = "Correct header syntax 'Authorization: APIKEY <your_key_here>'";
    /**
     * The constant APIKEY_PATTERN.
     */
    public static final String APIKEY_PATTERN                        = "APIKEY\\s+([^\\s]+)";
    /**
     * The constant CAPTCHA_PATTERN.
     */
    public static final String CAPTCHA_PATTERN                       = "Bearer\\s+([^\\s]+)";
    /**
     * The constant CAPTCHA_MISSING.
     */
    public static final String CAPTCHA_MISSING                       = "Missing or malformed Captcha token. Correct syntax header is: Authorization: Bearer CAPTCHA_TOKEN";
    /**
     * The constant CAPTCHA_VERIFICATION_FAILED.
     */
    public static final String CAPTCHA_VERIFICATION_FAILED           = "Captcha verification failed.";
    /**
     * The constant ERROR_COMMUNICATING_WITH_KEYCLOAK.
     */
    public static final String ERROR_COMMUNICATING_WITH_KEYCLOAK     = "Error communicating with Keycloak";
    /**
     * The constant RECEIVED.
     */
    public static final String RECEIVED                              = ": received ";
    /**
     * The constant AUTH_FAILED_CLIENT.
     */
    public static final String AUTH_FAILED_CLIENT                    = "Authentication failed for client %s";
    /**
     * The constant RETRIEVE_TOKEN_FAILED_FOR.
     */
    public static final String RETRIEVE_TOKEN_FAILED_FOR             = "Retrieving access token failed for client  %s";
    /**
     * The constant CLIENT_IS_ALREADY.
     */
    public static final String CLIENT_IS_ALREADY                     = "Client with id: {} and clientId: {} is already {}";

    /**
     * Template for client name
     */
    public static final String CLIENT_NAME                           = "%s (%s)";
    /**
     * Template for client description
     */
    public static final String CLIENT_DESCRIPTION                    = "%s %s (%s)";
    /**
     * Template for clients endpoint
     */
    public static final String CLIENTS_ENDPOINT                      = "%s/admin/realms/%s/clients";
    /**
     * Template for client-secret endpoint
     */
    public static final String CLIENT_SECRET_ENDPOINT                = "%s/admin/realms/%s/clients/%s/client-secret";
    /**
     * Template for clients update endpoint
     */
    public static final String CLIENTS_UPDATE_ENDPOINT               = "%s/admin/realms/%s/clients/%s";
    /**
     * Role for managing clients used to authorize access by Manager Client
     */
    public static final String MANAGE_CLIENTS_ROLE                   = "manage-clients";

    /**
     * hiding public constructor
     */
    private ApikeyDefinitions() {}


}
