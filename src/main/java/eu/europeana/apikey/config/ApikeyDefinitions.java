package eu.europeana.apikey.config;

/**
 * Created by luthien on 10/11/2020.
 */

public class ApikeyDefinitions {

    public static final String TO_MIGRATE_KEYCLOAKID                 = "to-migrate";
    public static final String MISSING_PARAMETER                     = "Missing parameter. ";
    public static final String BAD_EMAIL_FORMAT                      = "Email is not properly formatted.";
    public static final String APIKEY_NOT_REGISTERED                 = "API key %s is not registered";
    public static final String APIKEY_MISSING                        = "Correct header syntax 'Authorization: APIKEY <your_key_here>'";
    public static final String APIKEY_PATTERN                        = "APIKEY\\s+([^\\s]+)";
    public static final String CAPTCHA_PATTERN                       = "Bearer\\s+([^\\s]+)";
    public static final String CAPTCHA_MISSING                       = "Missing Captcha token in the header. Correct syntax: Authorization: Bearer CAPTCHA_TOKEN";
    public static final String CAPTCHA_VERIFICATION_FAILED           = "Captcha verification failed.";
    public static final String ERROR_COMMUNICATING_WITH_KEYCLOAK     = "Error communicating with Keycloak";
    public static final String RECEIVED                              = ": received ";

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
