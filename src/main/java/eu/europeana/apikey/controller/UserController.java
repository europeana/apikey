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

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.LocalDate;

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

    private static final Logger LOG = LogManager.getLogger(UserController.class);

    private final CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;
    private final KeycloakUserManager                  keycloakUserManager;
//    private final MailService                          emailService;

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

    private final CloseableHttpClient httpClient;

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
        if (httpClient != null){
            LOG.info("Closing http client ...");
            httpClient.close();
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
            HttpServletRequest request) {

        boolean       kcDeleted   = false;
        boolean       setsDeleted = false;
        StringBuilder reportMsg   = new StringBuilder("Result of delete request for userID ");
        String        userEmail   = "[unable to retrieve]";
        String        userId      = "unknown";
        String        userToken   = request.getHeader(HttpHeaders.AUTHORIZATION);


        try {

            if (StringUtils.isBlank(userToken)){
                return new ResponseEntity<>("No usertoken provided", HttpStatus.BAD_REQUEST);
            }
            userId = keycloakUserManager.extractUserId(userToken);

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
        } catch (MissingDataException mde) {
            LOG.error(mde.getMessage(), mde);
            return new ResponseEntity<>(mde.getError(), HttpStatus.BAD_REQUEST);
        } catch (MissingKCUserException mke) {
            return (handleKCUserErrorMessages(userId, userToken, "M",404, debug));
        } catch (KCComException kce) {
            return (handleKCUserErrorMessages(userId, userToken, "C", kce.getStatus(), debug));
        } catch (ForbiddenException fe) {
            return (handleKCUserErrorMessages(userId, userToken, "F", 0, debug));
        } catch (Exception e) {
            return (handleKCUserErrorMessages(userId, userToken, "U", 0, debug));
        }

        return new ResponseEntity<>(reportMsg.toString(), HttpStatus.NO_CONTENT);
    }


    /**
     * Configure sending "Keycloak communication error" or "user not found" message to Slack by HTTP or email.
     * The token is therefore logged in Kibana.
     *
     * @param userId        the userId as found in the supplied user token
     * @param userToken     the user token used to call this serviceuserToken
     * @param errorType     String defining error type to determine the message to be sent:
     *                      "M" if user cannot be found;
     *                      "C" in case of errors communicating with KeyCloak;
     *                      "F" if designated admin user isn't authorised; and
     *                      "U" for unknown / unexpected errors
     * @param debug         boolean if true: force the Slack send method to return false, triggering this method to also
     *                      send an email message
     * @return ResponseEntity with either HTTP NOT_FOUND (when user cannot be found) or HTTP BAD_GATEWAY (when there was
     * a problem communicating with Keycloak and / or when sending a message to Slack failed)
     */
    private ResponseEntity<Object> handleKCUserErrorMessages(String userId,
                                                             String userToken,
                                                             String errorType,
                                                             int kcStatus,
                                                             boolean debug) {
        String msgTemplate;
        StringBuilder message = new StringBuilder();
        String today = LocalDate.now().toString();
        HttpStatus    returnStatus;
        switch(errorType.toUpperCase()){
            case "C":
                msgTemplate = SLACK_KC_COMM_ISSUE_MESSAGEBODY;
                returnStatus = HttpStatus.BAD_GATEWAY;
                break;
            case "M":
                msgTemplate = SLACK_USER_NOTFOUND_MESSAGEBODY;
                returnStatus = HttpStatus.NOT_FOUND;
                break;
            case "F":
                msgTemplate = SLACK_FORBIDDEN_MESSAGEBODY;
                returnStatus = HttpStatus.FORBIDDEN;
                break;
            case "U":
                msgTemplate = SLACK_SERVICE_UNAVAILABLE_MESSAGEBODY;
                returnStatus = HttpStatus.SERVICE_UNAVAILABLE;
                break;
            default: // shouldn't happen, check if another call was added
                msgTemplate = SLACK_SERVICE_UNAVAILABLE_MESSAGEBODY;
                returnStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        }

        if (kcStatus == 0){
            message.append(String.format(msgTemplate, today, userId));
        } else {
            message.append(String.format(msgTemplate, today, userId, kcStatus));
        }

        if (!sendSlackErrorMessage(userId, errorType, kcStatus, debug) &&
            !sendErrorEmail(userId, errorType, kcStatus)) {
            message.insert(0, "Could not send the following message to Slack via HTTP nor email: ");
            returnStatus = HttpStatus.BAD_GATEWAY;
        }

        LOG.error("{} Supplied usertoken: {}", message, userToken);
        return new ResponseEntity<>(message.toString(), returnStatus);
    }

    private boolean sendSlackErrorMessage(String userId, String errorType, int kcStatus, boolean debug) {
        String messageBody;
        switch(errorType){
            case "C":
                messageBody = SLACK_KC_COMM_ISSUE_MESSAGEBODY;
                break;
            case "M":
                messageBody = SLACK_USER_NOTFOUND_MESSAGEBODY;
                break;
            case "F":
                messageBody = SLACK_FORBIDDEN_MESSAGEBODY;
                break;
            case "U":
                messageBody = SLACK_SERVICE_UNAVAILABLE_MESSAGEBODY;
                break;
            default: // shouldn't happen
                messageBody = SLACK_SERVICE_UNAVAILABLE_MESSAGEBODY;
        }
        return sendSlackMessage(String.format(messageBody,
                                              LocalDate.now().toString(),
                                              userId,
                                              kcStatus), debug);
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
        userDeletedSlackMail.setTo(slackEmail);
        return emailService.sendDeletedUserEmail(userDeletedSlackMail,
                                                 LocalDate.now().toString(),
                                                 userEmail,
                                                 kcDeleted ? OK_ASCII : ERROR_ASCII,
                                                 setsDeleted ? OK_ASCII : ERROR_ASCII,
                                                 LocalDate.now().plusDays(30).toString());
    }

    private boolean sendErrorEmail(String userId, String errorType, int status) {
        SimpleMailMessage mailTemplate;
        switch(errorType){
            case "C":
                mailTemplate = kcCommProblemSlackMail;
                mailTemplate.setSubject(SLACK_KC_COMM_ISSUE_MESSAGEBODY);
                break;
            case "M":
                mailTemplate = userNotFoundSlackMail;
                mailTemplate.setSubject(SLACK_USER_NOTFOUND_MESSAGEBODY);
                break;
            case "F":
                mailTemplate = kcForbiddenSlackMail;
                mailTemplate.setSubject(SLACK_FORBIDDEN_MESSAGEBODY);
                break;
            case "U":
                mailTemplate = unavailableSlackMail;
                mailTemplate.setSubject(SLACK_SERVICE_UNAVAILABLE_MESSAGEBODY);
                break;
            default: // shouldn't happen but just in case
                mailTemplate = unavailableSlackMail;
                mailTemplate.setSubject(SLACK_SERVICE_UNAVAILABLE_MESSAGEBODY);
        }
        mailTemplate.setTo(slackEmail);
        return emailService.sendUserProblemEmail(mailTemplate,
                                                 LocalDate.now().toString(),
                                                 userId,
                                                 status);
    }

    private boolean deleteUserSets(String userToken) {
        HttpDelete          httpDelete = new HttpDelete(userSetUrl);
        httpDelete.setHeader("Authorization", "Bearer " + userToken);

        try (CloseableHttpResponse response = httpClient.execute(httpDelete)) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.NO_CONTENT.value()) {
                return false;
            }
            httpClient.close();
        } catch (IOException e) {
            return false;
        }
        return true;
    }
}


