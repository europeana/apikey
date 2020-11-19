package eu.europeana.apikey.config;

/**
 * Created by luthien on 10/11/2020.
 */

public class ApikeyDefinitions {

    public static final String TO_MIGRATE_KEYCLOAKID                 = "to-migrate";
    public static final String MISSING_PARAMETER                     = "missing parameter";
    public static final String BAD_EMAIL_FORMAT                      = "Email is not properly formatted.";
    public static final String APIKEY_NOT_REGISTERED                 = "API key %s is not registered";
    public static final String APIKEY_MISSING                        = "Correct header syntax 'Authorization: APIKEY <your_key_here>'";
    public static final String APIKEY_PATTERN                        = "APIKEY\\s+([^\\s]+)";
    public static final String CAPTCHA_PATTERN                       = "Bearer\\s+([^\\s]+)";
    public static final String CAPTCHA_MISSING                       = "Missing Captcha token in the header. Correct syntax: Authorization: Bearer CAPTCHA_TOKEN";
    public static final String CAPTCHA_VERIFICATION_FAILED           = "Captcha verification failed.";
    public static final String MASTER_REALM                          = "master";
    public static final String ERROR_COMMUNICATING_WITH_KEYCLOAK     = "Error communicating with Keycloak";
    public static final String RECEIVED                              = ": received ";
    public static final String ERROR_ICON                            = ":x:";
    public static final String ERROR_ASCII                           = "✘";
    public static final String OK_ICON                               = ":heavy_check_mark:";
    public static final String OK_ASCII                              = "✓";

    private static final String REQUEST_RECEIVED                      = "{\"text\":\"On %s, a request was received to remove user account with ID %s.\\n\\n";
    private static final String NO_ACTION_BUT_LOGGED                  = "carrying out this request.\\nNo action was taken.\\nThe user token has been logged in Kibana.";
    private static final String NO_ACTION_BUT_LOGGED_PERIOD           = NO_ACTION_BUT_LOGGED + "\"}";
    private static final String NO_ACTION_LOGGED_AND_ERROR            = NO_ACTION_BUT_LOGGED + "\\n\\n[%s]\"}";

    public static final String SLACK_USER_DELETE_MESSAGEBODY         =
            "{\"text\":\"On %s, user %s has requested to remove their account.\\n" +
            "This has just been done automatically for those systems marked with :heavy_check_mark: :\\n\\n" +
            "[%s] Keycloak\\n" + "[%s] The User Sets API\\n" + "[:x:] The recommendation engine\\n" +
            "[:x:] Mailchimp\\n\\n" +
            "From the remaining systems (marked with :x: above) their account should be removed within 30 days (before %s).\"}";
    public static final String SLACK_USER_NOTFOUND_MESSAGEBODY       =
            REQUEST_RECEIVED + "this userID could not be found in Keycloak (HTTP %d), which might indicate a problem " +
            "with the token used to send the request. Therefore the token has been logged in Kibana.\"}";
    public static final String SLACK_KC_COMM_ISSUE_MESSAGEBODY       =
            REQUEST_RECEIVED + "there was a problem connecting to " + "Keycloak (HTTP %d), preventing " +
            NO_ACTION_BUT_LOGGED_PERIOD;
    public static final String SLACK_FORBIDDEN_MESSAGEBODY           =
            REQUEST_RECEIVED + "an authorisation/authentication problem for the embedded Keycloak User prevented " +
            NO_ACTION_LOGGED_AND_ERROR;
    public static final String SLACK_SERVICE_UNAVAILABLE_MESSAGEBODY =
            REQUEST_RECEIVED + "a server error occurred which prevented " + NO_ACTION_BUT_LOGGED_PERIOD;

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
     * Template for users endpoint
     */
    public static final String USER_ENDPOINT                         = "%s/admin/realms/%s/users/%s";
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
