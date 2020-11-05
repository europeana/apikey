package eu.europeana.apikey.controller;

import eu.europeana.apikey.exception.*;
import eu.europeana.apikey.keycloak.*;
import eu.europeana.apikey.mail.MailService;
import io.micrometer.core.instrument.util.StringUtils;
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

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.LocalDate;

/**
 * Handles incoming requests to delete Keycloak users
 * <p>
 * Created by luthien on 01/10/2020.
 * This controller implements the delete Keycloak user functionality from ticket EA-2234
 */
@RestController
@RequestMapping("/user")
public class UserController {


    private static final Logger                               LOG                             = LogManager.getLogger(
            UserController.class);
    private static final String                               ERROR_ICON                      = ":x:";
    private static final String                               ERROR_ASCII                     = "✘";
    private static final String                               OK_ICON                         = ":heavy_check_mark:";
    private static final String                               OK_ASCII                        = "✓";
    private static final String                               SLACK_USER_DELETE_MESSAGEBODY   =
            "{\"text\":\"On %s, user %s has requested to remove their account.\\n" +
            "This has just been done automatically for those systems marked with :heavy_check_mark: :\\n\\n" +
            "[%s] Keycloak\\n" + "[%s] The User Sets API\\n" + "[:x:] The recommendation engine\\n" +
            "[:x:] Mailchimp\\n\\n" +
            "From the remaining systems (marked with :x: above) their account should be removed within 30 days (before %s).\"}";
    private static final String                               SLACK_USER_NOTFOUND_MESSAGEBODY =
            "{\"text\":\"On %s, a request was received to remove user account with ID %s.\\n\\n" +
            "This userID could not be found in Keycloak (HTTP %d), which might indicate a problem " +
            "with the token used to send the request. Therefore the token has been logged in Kibana.\"}";
    private static final String                               SLACK_KC_COMM_ISSUE_MESSAGEBODY =
            "{\"text\":\"On %s, a request was received to remove user account with ID %s.\\n\\n" +
            "There was a problem connecting to Keycloak (HTTP %d), so no action could be taken.\\n" +
            "The user token has been logged in Kibana.\"}";
    private final        CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;
    private final        KeycloakUserManager                  keycloakUserManager;
    private final        MailService                          emailService;
    private final        SimpleMailMessage                    userDeletedSlackMail;
    private final        SimpleMailMessage                    userNotFoundSlackMail;
    private final        SimpleMailMessage                    kcCommProblemSlackMail;

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

    private CloseableHttpClient httpClient;

    @Autowired
    public UserController(CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider,
                          MailService emailService,
                          @Qualifier("userDeletedMail") SimpleMailMessage userDeletedSlackMail,
                          @Qualifier("userNotFoundMail") SimpleMailMessage userNotFoundSlackMail,
                          @Qualifier("kcCommProblemMail") SimpleMailMessage kcCommProblemSlackMail,
                          KeycloakUserManager keycloakUserManager) {
        this.customKeycloakAuthenticationProvider = customKeycloakAuthenticationProvider;
        this.keycloakUserManager = keycloakUserManager;
        this.emailService = emailService;
        this.userDeletedSlackMail = userDeletedSlackMail;
        this.userNotFoundSlackMail = userNotFoundSlackMail;
        this.kcCommProblemSlackMail = kcCommProblemSlackMail;

    }

    @PostConstruct
    public void init() {
        httpClient = HttpClients.createDefault();
    }

    @PreDestroy
    public void clean() {
        try {
            httpClient.close();
        } catch (IOException e) {
            LOG.error("Closing http client failed", e);
        }
    }

    @CrossOrigin(maxAge = 600)
    @GetMapping(path = "/hello/{id}", produces = MediaType.TEXT_PLAIN_VALUE)
    public String read(@PathVariable("id") String id) {
        return "Hello there " + id;
    }

    /**
     * retrieve access token for the admin user so we can use that to list & delete the user
     * because users themselves are not authorised to delete their accounts in Keycloak
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/delete")
    public ResponseEntity<Object> delete(
            @RequestParam(value = "debug", required = false, defaultValue = "false") boolean debug,
            HttpServletRequest request) throws ApiKeyException {
        StringBuilder reportMsg   = new StringBuilder("Result of delete request for userID ");
        boolean       kcDeleted   = false;
        boolean       setsDeleted = false;
        String        userToken   = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isBlank(userToken)){
            return new ResponseEntity<>("No usertoken provided", HttpStatus.BAD_REQUEST);
        }
        String        userEmail   = "[unable to retrieve]";
        String        userId;

        try {
            userId = keycloakUserManager.extractUserId(userToken);
        } catch (MissingDataException mde) {
            return new ResponseEntity<>(mde.getError(), HttpStatus.BAD_REQUEST);
        }

        LOG.info("Processing delete request for userID {}", userId);

        KeycloakAuthenticationToken adminAuthToken = (KeycloakAuthenticationToken) customKeycloakAuthenticationProvider.authenticateAdminUser(
                adminUserName,
                adminUserPassword,
                adminUserClientId,
                adminUserGrantType);

        if (adminAuthToken == null) {
            LOG.error("Error requesting admin level token: aborted processing delete request ");
            throw new ForbiddenException();
        }

        reportMsg.append(". Sending delete request to User Sets Api: [");
        if (deleteUserSets(userToken)) {
            setsDeleted = true;
            reportMsg.append("OK] ;");
        } else {
            reportMsg.append("FAILED] ;");
        }
        LOG.info("Deleting User Sets {}", setsDeleted ? "succeeded" : "failed");

        if (StringUtils.isNotBlank(userId)) {
            reportMsg.append(" sending User delete request to Keycloak: [");
            UserRepresentation userRep;

            try {
                userRep = keycloakUserManager.userDetails(userId,
                                                          (KeycloakSecurityContext) adminAuthToken.getCredentials());
            } catch (MissingKCUserException e) {
                return (handleKCUserErrorMessages(userId, userToken, 404, false, debug));
            } catch (KCComException e) {
                return (handleKCUserErrorMessages(userId, userToken, e.getStatus(), true, debug));
            }

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

        if (!prepareUserDeleteSlackMessage(userEmail, kcDeleted, setsDeleted, debug)) {
            if (!sendUserDeletedSlackEmail(userEmail, kcDeleted, setsDeleted)) {
                reportMsg.insert(0, "Error sending User delete request report to Slack: ");
                LOG.error(reportMsg);
                return new ResponseEntity<>(reportMsg, HttpStatus.BAD_GATEWAY);
            } else {
                reportMsg.insert(0,
                                 "Error sending User delete request report to Slack via HTTP Post webhook." +
                                 "The message was successfully sent via email instead: ");
                LOG.warn(reportMsg);
            }
        } else {
            LOG.info(reportMsg);
        }
        return new ResponseEntity<>(reportMsg.toString(), HttpStatus.NO_CONTENT);
    }


    /**
     * Configure sending "Keycloak communication error" or "user not found" message to Slack by HTTP or email.
     * The token is therefore logged in Kibana.
     *
     * @param userId        the userId as found in the supplied user token
     * @param userToken     the user token used to call this serviceuserToken
     * @param kcCommProblem boolean true: send "keycloak comm error messages"; false: send "user not found" messages
     * @param debug         boolean if true: force the Slack send method to return false, triggering this method to also
     *                      send an email message
     * @return ResponseEntity with either HTTP NOT_FOUND (when user cannot be found) or HTTP BAD_GATEWAY (when there was
     * a problem communicating with Keycloak and / or when sending a message to Slack failed)
     */
    private ResponseEntity<Object> handleKCUserErrorMessages(String userId,
                                                             String userToken,
                                                             int status,
                                                             boolean kcCommProblem,
                                                             boolean debug) {
        HttpStatus    returnStatus = kcCommProblem ? HttpStatus.BAD_GATEWAY : HttpStatus.NOT_FOUND;
        StringBuilder msg          = new StringBuilder();

        if (!prepareKCUserProblemEmail(userId, status, kcCommProblem, debug) &&
            !sendUserProblemEmail(userId, status, kcCommProblem)) {
            msg.append("Could not send the following message to Slack via HTTP nor email: ");
            returnStatus = HttpStatus.BAD_GATEWAY;
        }
        msg.append("On ")
           .append(LocalDate.now().toString())
           .append(", a request was received to remove user account with ID ")
           .append(userId);

        if (kcCommProblem){
            msg.append(". There was a problem connecting to Keycloak (HTTP ").append(status)
               .append(") so no action could be taken.");
        } else {
            msg.append(". This userID could not be found in Keycloak, which might indicate a problem " +
                       "with the token used to send the request.");
        }
        LOG.error("{} Supplied usertoken: {}", msg, userToken);
        msg.append(" Therefore the token has been logged in Kibana.");
        return new ResponseEntity<>(msg, returnStatus);
    }

    private boolean prepareKCUserProblemEmail(String userId, int status, boolean kcCommProblem, boolean debug) {
        return sendSlackMessage(String.format(kcCommProblem ? SLACK_KC_COMM_ISSUE_MESSAGEBODY : SLACK_USER_NOTFOUND_MESSAGEBODY,
                                              LocalDate.now().toString(),
                                              userId,
                                              status), debug);
    }


    /**
     * Configure post request sending the User delete confirmation to Slack
     *
     * @param userEmail   email address of the User to delete
     * @param kcDeleted   boolean representing success or failure deleting KC user
     * @param setsDeleted boolean representing success or failure deleting user sets
     * @param debug       boolean if true: force the Slack send method to return false, triggering this method to also
     *                    send an email message
     * @return boolean whether or not sending the message succeeded
     */
    private boolean prepareUserDeleteSlackMessage(String userEmail,
                                                  boolean kcDeleted,
                                                  boolean setsDeleted,
                                                  boolean debug) {
        return sendSlackMessage(String.format(SLACK_USER_DELETE_MESSAGEBODY,
                                              LocalDate.now().toString(),
                                              userEmail,
                                              kcDeleted ? OK_ICON : ERROR_ICON,
                                              setsDeleted ? OK_ICON : ERROR_ICON,
                                              LocalDate.now().plusDays(30).toString()), debug);
    }

    private boolean sendSlackMessage(String json, boolean debug) {
        StringEntity        entity;
        HttpPost            httpPost = new HttpPost(slackWebHook);

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
     * Configure send results of user delete request to Slack by email
     *
     * @param userEmail   email address of the User to delete
     * @param kcDeleted   boolean representing success or failure deleting KC user
     * @param setsDeleted boolean representing success or failure deleting user sets
     * @return boolean whether or not sending the message succeeded
     */
    private boolean sendUserDeletedSlackEmail(String userEmail, boolean kcDeleted, boolean setsDeleted) {
        return emailService.sendDeletedUserEmail(slackEmail,
                                                 "Auth user service: result of user delete request",
                                                 userDeletedSlackMail,
                                                 LocalDate.now().toString(),
                                                 userEmail,
                                                 kcDeleted ? OK_ASCII : ERROR_ASCII,
                                                 setsDeleted ? OK_ASCII : ERROR_ASCII,
                                                 LocalDate.now().plusDays(30).toString());
    }

    private boolean sendUserProblemEmail(String userId, int status, boolean kcCommProblem) {
        return emailService.sendUserProblemEmail(slackEmail,
                                                 "Auth user service: " +
                                                 (kcCommProblem ? "could not connect to Keycloak" : "userId from token not found in Keycloak"),
                                                 kcCommProblem ? kcCommProblemSlackMail : userNotFoundSlackMail,
                                                 LocalDate.now().toString(),
                                                 userId,
                                                 status);
    }

    private boolean deleteUserSets(String userToken) {
        CloseableHttpClient client     = HttpClients.createDefault();
        HttpDelete          httpDelete = new HttpDelete(userSetUrl);

        httpDelete.setHeader("Authorization", "Bearer " + userToken);

        try (CloseableHttpResponse response = client.execute(httpDelete)) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.NO_CONTENT.value()) {
                return false;
            }
            client.close();
        } catch (IOException e) {
            return false;
        }
        return true;
    }
}


