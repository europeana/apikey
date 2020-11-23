package eu.europeana.apikey.controller;

import eu.europeana.apikey.exception.*;
import eu.europeana.apikey.keycloak.*;
import eu.europeana.apikey.mail.MailService;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PreDestroy;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.LocalDate;
import java.util.Collections;

import static eu.europeana.apikey.config.ApikeyDefinitions.*;

/**
 * Handles incoming requests to delete Keycloak users
 * <p>
 * Created by luthien on 01/10/2020.
 * This controller implements the delete Keycloak user functionality from ticket EA-2234
 */
@RestController
@RequestMapping("/user")
public class UserController {

    private static final Logger LOG      = LogManager.getLogger(UserController.class);
    private static final String RESPONSE = "response";

    private final CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;
    private final KeycloakUserManager                  keycloakUserManager;
    private final CloseableHttpClient                  httpClient;

    @Autowired
    private MailService emailService;

    @Value("${keycloak.user.admin.username}")
    private String adminUserName;

    @Value("${keycloak.user.admin.password}")
    private String adminUserPassword;

    @Value("${keycloak.user.admin.clientid}")
    private String adminUserClientId;

    @Value("${keycloak.user.admin.granttype}")
    private String adminUserGrantType;

    @Value("${keycloak.user.slack.webhook}")
    private String slackWebHook;

    @Value("${keycloak.user.slack.email}")
    private String slackEmail;

    @Value("${keycloak.set.api.url}")
    private String userSetUrl;

    @Autowired
    @Qualifier("userDeletedTemplate")
    private SimpleMailMessage userDeletedSlackMail;

    @Autowired
    @Qualifier("userNotFoundTemplate")
    private SimpleMailMessage userNotFoundSlackMail;

    @Autowired
    @Qualifier("kcCommProblemTemplate")
    private SimpleMailMessage kcCommProblemSlackMail;

    @Autowired
    @Qualifier("forbiddenTemplate")
    private SimpleMailMessage kcForbiddenSlackMail;

    @Autowired
    @Qualifier("unavailableTemplate")
    private SimpleMailMessage unavailableSlackMail;

    @Autowired
    public UserController(CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider,
                          KeycloakUserManager keycloakUserManager) {
        this.customKeycloakAuthenticationProvider = customKeycloakAuthenticationProvider;
        this.keycloakUserManager = keycloakUserManager;
        httpClient = HttpClients.createDefault();
    }

    @PreDestroy
    public void close() throws IOException {
        if (httpClient != null) {
            LOG.info("Closing http client ...");
            httpClient.close();
        }
    }

    /**
     * Testing
     */
    @CrossOrigin(maxAge = 600)
    @GetMapping(path = "/hello/{id}", produces = MediaType.TEXT_PLAIN_VALUE)
    public String read(@PathVariable("id") String id) {
        return "Hello there " + id;
    }

    /**
     * Deletes a Keycloak user identified by the token that is to be supplied in the Authorization header,
     * as well as the user sets that user has created in the Set Api.
     * The actual delete request is sent by the admin user stored in the properties file because Keycloak Users
     * can not delete their own account.
     * <p>
     * The following return statuses are possible:
     * HTTP 204 NO_CONTENT            if the user is deleted successfully
     * HTTP 400 BAD_REQUEST           if required data are missing (eg in the supplied token)
     * HTTP 401 UNAUTHORIZED          if there is a problem obtaining authorisation / authentication for the admin user
     * HTTP 404 NOT_FOUND             if the Keycloak user cannot be found
     * HTTP 500 INTERNAL_SERVER_ERROR if an unexpected error occurs
     * HTTP 502 BAD_GATEWAY           if there is an error communicating with Keycloak other then obtaining admin access
     * HTTP 503 SERVICE_UNAVAILABLE   for non-specified server errors
     * <p>
     * The results of the delete operation and possible error conditions will be sent to the dedicated Slack channel
     * using a HTTP Post request. If that fails, the same message will be sent via email. If that fails as well, the
     * message is logged to Kibana.
     *
     * @param debug if true, the code will send an email message to Slack also when the HTTP Post request succeeds
     * @return ResponseEntity containing appropriate HTTP status and results summary.
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/delete")
    public ResponseEntity<Object> delete(
            @RequestParam(value = "debug", required = false, defaultValue = "false") boolean debug,
            HttpServletRequest request) {

        boolean       kcDeleted   = false;
        boolean       setsDeleted = false;
        StringBuilder reportMsg   = new StringBuilder("Result of delete request for userID ");
        String        userEmail   = "[unable to retrieve]";
        String        userId      = "unknown";
        String        userToken   = request.getHeader(HttpHeaders.AUTHORIZATION);

        try {
            if (StringUtils.isBlank(userToken)) {
                return new ResponseEntity<>(Collections.singletonMap(RESPONSE, "No usertoken provided"),
                                            HttpStatus.BAD_REQUEST);
            }
            userId = keycloakUserManager.extractUserId(userToken);
            reportMsg.append(userId);

            LOG.info("Processing delete request for userID {} ...", userId);

            KeycloakAuthenticationToken adminAuthToken = (KeycloakAuthenticationToken) customKeycloakAuthenticationProvider
                    .authenticateAdminUser(adminUserName, adminUserPassword, adminUserClientId, adminUserGrantType);

            if (adminAuthToken == null) {
                LOG.error("Error requesting admin level token: aborted processing delete request ");
                throw new KCAuthException("aborted processing delete request", "could not acquire admin level token");
            }
            reportMsg.append(": sending delete request to User Sets Api: [");
            if (deleteUserSets(userToken)) {
                setsDeleted = true;
                reportMsg.append("OK] ;");
            } else {
                reportMsg.append("FAILED] ;");
            }
            LOG.info("Deleting User Sets {}", setsDeleted ? "succeeded" : "failed");

            if (StringUtils.isNotBlank(userId)) {
                reportMsg.append(" sending User delete request to Keycloak: [");
                UserRepresentation userRep = keycloakUserManager.userDetails(userId,
                                                                             (KeycloakSecurityContext) adminAuthToken.getCredentials());
                userEmail = userRep.getEmail();

                LOG.info("UserID: {}, name: {} found in Keycloak; sending delete request ... ",
                         userId,
                         userRep.getUsername());

                if (keycloakUserManager.deleteUser(userId, (KeycloakSecurityContext) adminAuthToken.getCredentials())) {
                    kcDeleted = true;
                    reportMsg.append("OK]");
                } else {
                    reportMsg.append("FAILED]");
                }
            } else {
                reportMsg.append("FAILED]");
            }

            LOG.info("Deleting userID {} from Keycloak {}", userId, kcDeleted ? "succeeded" : "failed");

            if (!prepareUserDeletedMessage(userEmail, kcDeleted, setsDeleted, debug)) {
                if (!sendUserDeletedEmail(userEmail, kcDeleted, setsDeleted)) {
                    reportMsg.insert(0, "Error sending User delete request report to Slack: ");
                    LOG.error(reportMsg);
                    return new ResponseEntity<>(Collections.singletonMap(RESPONSE, reportMsg), HttpStatus.BAD_GATEWAY);
                } else {
                    reportMsg.insert(0,
                                     "Error sending User delete request report to Slack via HTTP Post webhook. " +
                                     "This message was sent successfully via email -> ");
                    LOG.warn(reportMsg);
                }
            } else {
                LOG.info(reportMsg);
            }
        } catch (MissingDataException mde) {
            LOG.error(mde.getMessage(), mde);
            return new ResponseEntity<>(Collections.singletonMap(RESPONSE, mde.getError()), HttpStatus.BAD_REQUEST);
        } catch (MissingKCUserException mke) {
            return (handleErrorMessages(userId, userToken, "M", "", 404, debug));
        } catch (KCAuthException kca) {
            return (handleErrorMessages(userId, userToken, "F", kca.getErrorAndCause(), 0, debug));
        } catch (KCComException kce) {
            return (handleErrorMessages(userId, userToken, "C", "", kce.getStatus(), debug));
        } catch (Exception e) {
            return (handleErrorMessages(userId, userToken, "U", "", 0, debug));
        }

        return new ResponseEntity<>(Collections.singletonMap(RESPONSE, reportMsg.toString()), HttpStatus.NO_CONTENT);
    }


    /**
     * Configure sending "Keycloak communication error" or "user not found" message to Slack by HTTP or email.
     * The token is therefore logged in Kibana.
     *
     * @param userId       the userId as found in the supplied user token
     * @param userToken    the user token used to call this serviceuserToken
     * @param errorType    String defining error type to determine the message to be sent:
     *                     "M" if user cannot be found;
     *                     "C" in case of errors communicating with KeyCloak;
     *                     "F" if designated admin user isn't authorised; and
     *                     "U" for unknown / unexpected errors
     * @param errorMessage additional information about the encountered error (if applicable)
     * @param debug        boolean TRUE: force sending an email message to Slack even when the HTTP Post request succeeds
     * @return ResponseEntity with either HTTP NOT_FOUND (when user cannot be found) or HTTP BAD_GATEWAY (when there was
     * a problem communicating with Keycloak and / or when sending a message to Slack failed)
     */
    private ResponseEntity<Object> handleErrorMessages(String userId,
                                                       String userToken,
                                                       String errorType,
                                                       String errorMessage,
                                                       int kcStatus,
                                                       boolean debug) {
        StringBuilder message = new StringBuilder();
        String        today   = LocalDate.now().toString();
        HttpStatus    returnStatus;
        switch (errorType.toUpperCase()) {
            case "C":
                message.append(String.format(SLACK_KC_COMM_ISSUE_MESSAGEBODY, today, userId, kcStatus));
                returnStatus = HttpStatus.BAD_GATEWAY;
                break;
            case "M":
                message.append(String.format(SLACK_USER_NOTFOUND_MESSAGEBODY, today, userId, kcStatus));
                returnStatus = HttpStatus.NOT_FOUND;
                break;
            case "F":
                message.append(String.format(SLACK_FORBIDDEN_MESSAGEBODY, today, userId, errorMessage));
                returnStatus = HttpStatus.UNAUTHORIZED;
                break;
            case "U":
                message.append(String.format(SLACK_SERVICE_UNAVAILABLE_MESSAGEBODY, today, userId));
                returnStatus = HttpStatus.SERVICE_UNAVAILABLE;
                break;
            default: // shouldn't happen, check if another errorType was added
                message.append(String.format(SLACK_SERVICE_UNAVAILABLE_MESSAGEBODY, today, userId));
                returnStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        }

        if (!sendMessage(message.toString(), debug) && !sendErrorEmail(userId, errorType, kcStatus)) {
            message.insert(0, "Could not send the following message to Slack via HTTP nor email: ");
            returnStatus = HttpStatus.BAD_GATEWAY;
        }

        LOG.error("{} Supplied usertoken: {}", message, userToken);
        return new ResponseEntity<>(Collections.singletonMap(RESPONSE, message.toString()), returnStatus);
    }

    /**
     * Configure post request sending the User delete confirmation to Slack
     *
     * @param userEmail   email address of the User to delete
     * @param kcDeleted   boolean representing success or failure deleting KC user
     * @param setsDeleted boolean representing success or failure deleting user sets
     * @param debug       boolean TRUE: force sending an email message to Slack even when the HTTP Post request succeeds
     * @return boolean whether or not sending the message succeeded
     */
    private boolean prepareUserDeletedMessage(String userEmail, boolean kcDeleted, boolean setsDeleted, boolean debug) {
        return sendMessage(String.format(SLACK_USER_DELETE_MESSAGEBODY,
                                         LocalDate.now().toString(),
                                         userEmail,
                                         kcDeleted ? OK_ICON : ERROR_ICON,
                                         setsDeleted ? OK_ICON : ERROR_ICON,
                                         LocalDate.now().plusDays(30).toString()), debug);
    }

    /**
     * Send message to the Slack channel with a POST HTTP request
     *
     * @param json  contents of the messages
     * @param debug boolean true: force sending an email message to Slack even when the HTTP Post request succeeds
     *              sends an email message
     * @return boolean whether or not sending the message succeeded
     */
    private boolean sendMessage(String json, boolean debug) {
        StringEntity entity;
        HttpPost     httpPost = new HttpPost(slackWebHook);

        try {
            entity = new StringEntity(json);
        } catch (UnsupportedEncodingException e) {
            return false;
        }

        httpPost.setEntity(entity);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/json");

        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.OK.value()) {
                return false;
            }
        } catch (IOException e) {
            return false;
        }
        return !debug;
    }

    /**
     * Sends the results of the user delete request to Slack by email
     *
     * @param userEmail   email address of the User to delete
     * @param kcDeleted   boolean representing success or failure deleting KeyCloak user
     * @param setsDeleted boolean representing success or failure deleting user sets
     * @return boolean whether or not sending the message succeeded
     */
    private boolean sendUserDeletedEmail(String userEmail, boolean kcDeleted, boolean setsDeleted) {
        userDeletedSlackMail.setTo(slackEmail);
        return emailService.sendDeletedUserEmail(userDeletedSlackMail,
                                                 LocalDate.now().toString(),
                                                 userEmail,
                                                 kcDeleted ? OK_ASCII : ERROR_ASCII,
                                                 setsDeleted ? OK_ASCII : ERROR_ASCII,
                                                 LocalDate.now().plusDays(30).toString());
    }

    /**
     * Sends a report about errors that occurred while processing the user delete request to Slack using email
     *
     * @param userId    user id as found in the User Token. If this could not be retrieved, it will default to "unknown"
     * @param errorType String defining error type to determine the contents of the email to be sent:
     *                  "M" if user cannot be found;
     *                  "C" in case of errors communicating with KeyCloak;
     *                  "F" if designated admin user isn't authorised; and
     *                  "U" for unknown / unexpected errors
     * @param status    int value representing the HTTP return status of
     * @return boolean whether or not sending the message succeeded
     */
    private boolean sendErrorEmail(String userId, String errorType, int status) {
        SimpleMailMessage mailTemplate;
        switch (errorType) {
            case "C":
                mailTemplate = kcCommProblemSlackMail;
                break;
            case "M":
                mailTemplate = userNotFoundSlackMail;
                break;
            case "F":
                mailTemplate = kcForbiddenSlackMail;
                break;
            case "U":
                mailTemplate = unavailableSlackMail;
                break;
            default: // shouldn't happen but just in case
                mailTemplate = unavailableSlackMail;
        }
        mailTemplate.setTo(slackEmail);
        return emailService.sendUserProblemEmail(mailTemplate, LocalDate.now().toString(), userId, status);
    }

    private boolean deleteUserSets(String userToken) {
        HttpDelete httpDelete = new HttpDelete(userSetUrl);
        httpDelete.setHeader("Authorization", "Bearer " + userToken);

        try (CloseableHttpResponse response = httpClient.execute(httpDelete)) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.NO_CONTENT.value()) {
                return false;
            }
        } catch (IOException e) {
            return false;
        }
        return true;
    }
}


