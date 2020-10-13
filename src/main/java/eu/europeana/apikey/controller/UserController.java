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
import java.util.Date;

/**
 * Handles incoming requests to delete Keycloak users
 * <p>
 * Created by luthien on 01/10/2020.
 * This controller implements the delete Keycloak user functionality from ticket EA-2234
 */
@RestController
@RequestMapping("/user")
public class UserController {


    private static final Logger                               LOG = LogManager.getLogger(UserController.class);
    private static final String ERROR_ICON  = ":x:";
    private static final String ERROR_ASCII = "X";
    private static final String OK_ICON     = ":heavy_check_mark:";
    private static final String OK_ASCII    = "V";
    private final        CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;
    private final        KeycloakUserManager                  keycloakUserManager;
    private final        MailService                          emailService;
    private final        SimpleMailMessage                    userDeletedSlackMail;
    private static final String SLACKMESSAGEBODY =
            "{\"text\":\"User %s has requested to remove their account.\\n" +
            "This has just been done for the systems marked with :heavy_check_mark: :\\n\\n" +
            "[%s] Keycloak\\n" +
            "[%s] The User Sets API\\n" +
            "[:x:] The recommendation engine\\n" +
            "[:x:] Mailchimp\\n\\n" +
            "The date of their request is %tc. \\n" +
            "Please remove their account from the services marked with :x: within 30 days from this date.\"}";
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
                          @Qualifier("slackMail") SimpleMailMessage userDeletedSlackMail,
                          KeycloakUserManager keycloakUserManager) {
        this.customKeycloakAuthenticationProvider = customKeycloakAuthenticationProvider;
        this.keycloakUserManager = keycloakUserManager;
        this.emailService = emailService;
        this.userDeletedSlackMail = userDeletedSlackMail;
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
    public ResponseEntity<String> delete(HttpServletRequest request) throws ApiKeyException {
        StringBuilder reportMsg   = new StringBuilder("Result of User delete request:");
        boolean       kcDeleted   = false;
        boolean       setsDeleted = false;
        String userToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        String userEmail = "[unable to retrieve]";

        KeycloakAuthenticationToken adminAuthToken = (KeycloakAuthenticationToken) customKeycloakAuthenticationProvider.authenticateAdminUser(
                adminUserName,
                adminUserPassword,
                adminUserClientId,
                adminUserGrantType);

        if (adminAuthToken == null) {
            throw new ForbiddenException();
        }

        reportMsg.append(" sending delete request to User Sets Api: [");
        if (deleteUserSets(userToken)) {
            setsDeleted = true;
            reportMsg.append("OK] ;");
        } else {
            reportMsg.append("FAILED] ;");
        }

        String userId = keycloakUserManager.extractUserId(userToken);
        reportMsg.append(" sending User delete request to Keycloak: [");

        if (StringUtils.isNotBlank(userId)) {
            UserRepresentation userRep = keycloakUserManager.userDetails(userId,
                                                                         (KeycloakSecurityContext) adminAuthToken.getCredentials());
            userEmail = userRep.getEmail();
            LOG.info("Sending delete request to Keycloak for user with ID: {}, name: {}",
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

        if (!sendSlackMessage(userEmail, kcDeleted, setsDeleted)) {
            if (!sendSlackEmail(userEmail, kcDeleted, setsDeleted)) {
                String errorMessage = "Error sending User delete request message to Slack. " + reportMsg.toString();
                LOG.error(errorMessage);
                return new ResponseEntity<>(errorMessage, HttpStatus.BAD_GATEWAY);
            }
        }

        LOG.info(reportMsg.toString());
        return new ResponseEntity<>(reportMsg.toString(), HttpStatus.NO_CONTENT);
    }
    /**
     * Configure post request sending the User delete confirmation to Slack
     *
     * @param userEmail   email address of the User to delete
     * @param kcDeleted   boolean representing success or failure deleting KC user
     * @param setsDeleted boolean representing success or failure deleting user sets
     * @return boolean whether or not sending the message succeeded
     */
    private boolean sendSlackMessage(String userEmail, boolean kcDeleted, boolean setsDeleted) {
        StringEntity        entity;
        CloseableHttpClient client   = HttpClients.createDefault();
        HttpPost            httpPost = new HttpPost(slackWebHook);

        String json = String.format(SLACKMESSAGEBODY,
                                    userEmail,
                                    kcDeleted ? OK_ICON : ERROR_ICON,
                                    setsDeleted ? OK_ICON : ERROR_ICON,
                                    new Date());
        try {
            entity = new StringEntity(json);
        } catch (UnsupportedEncodingException e) {
            return false;
        }

        httpPost.setEntity(entity);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/json");

        try (CloseableHttpResponse response = client.execute(httpPost)) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.OK.value()) {
                return false;
            }
            client.close();
        } catch (IOException e) {
            return false;
        }
        return false;
//        return true;
    }

    /**
     * Configure send results of user delete request to Slack by email
     *
     * @param userEmail   email address of the User to delete
     * @param kcDeleted   boolean representing success or failure deleting KC user
     * @param setsDeleted boolean representing success or failure deleting user sets
     * @return boolean whether or not sending the message succeeded
     */
    private boolean sendSlackEmail(String userEmail, boolean kcDeleted, boolean setsDeleted) {
        return emailService.sendSimpleSlackMessage(slackEmail,
                                                   "Result of User delete request",
                                                   userDeletedSlackMail,
                                                   userEmail,
                                                   kcDeleted ? OK_ASCII : ERROR_ASCII,
                                                   setsDeleted ? OK_ASCII : ERROR_ASCII,
                                                   new Date());
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


