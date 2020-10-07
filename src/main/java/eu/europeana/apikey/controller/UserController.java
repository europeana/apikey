package eu.europeana.apikey.controller;

import eu.europeana.apikey.captcha.CaptchaManager;
import eu.europeana.apikey.exception.*;
import eu.europeana.apikey.keycloak.*;
import eu.europeana.apikey.mail.MailService;
import io.micrometer.core.instrument.util.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
    private final MailService                          emailService;
    private final SimpleMailMessage                    apiKeyCreatedMail;
    private final KeycloakUserManager                  keycloakUserManager;
    private final String slackMessageBody = "{\"text\":\"User account with ID: %s, email %s has been deleted from Keycloak.\"}";
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

    private CloseableHttpClient httpClient;

    @Autowired
    public UserController(CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider,
                          MailService emailService,
                          SimpleMailMessage apiKeyCreatedMail,
                          KeycloakUserManager keycloakUserManager) {
        this.customKeycloakAuthenticationProvider = customKeycloakAuthenticationProvider;
        this.emailService = emailService;
        this.apiKeyCreatedMail = apiKeyCreatedMail;
        this.keycloakUserManager = keycloakUserManager;
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
    public ResponseEntity<HttpStatus> delete(HttpServletRequest request) throws ApiKeyException {

        String userToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        KeycloakAuthenticationToken adminAuthToken = (KeycloakAuthenticationToken) customKeycloakAuthenticationProvider.authenticateAdminUser(
                adminUserName,
                adminUserPassword,
                adminUserClientId,
                adminUserGrantType);

        if (adminAuthToken == null) {
            throw new ForbiddenException();
        }

        String userId = keycloakUserManager.extractUserId(userToken);

        if (StringUtils.isNotBlank(userId)) {
            UserRepresentation userRep = keycloakUserManager.userDetails(userId,
                                                                         (KeycloakSecurityContext) adminAuthToken.getCredentials());

            LOG.info("Deleting user with ID: {}, name: {}", userId, userRep.getUsername());
            keycloakUserManager.deleteUser(userId, (KeycloakSecurityContext) adminAuthToken.getCredentials());
            if (!sendSlackMessage(userId, userRep.getEmail())){
                return new ResponseEntity<>(HttpStatus.BAD_GATEWAY);
            }
        }
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }


    /**
     * Configure post request sending the User delete confirmation to Slack
     *
     * @param userId api key used as keycloak userId
     * @param email  access token to authorize request
     * @return configured HttpGet request
     */
    private boolean sendSlackMessage(String userId, String email) {
        StringEntity        entity;
        CloseableHttpClient client   = HttpClients.createDefault();
        HttpPost            httpPost = new HttpPost(slackWebHook);

        String json = String.format(slackMessageBody, userId, email);

        try {
            entity = new StringEntity(json);
        } catch (UnsupportedEncodingException e) {
            return false;
        }

        httpPost.setEntity(entity);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/json");

        try (CloseableHttpResponse response = client.execute(httpPost)) {
            if (response.getStatusLine().getStatusCode() != org.apache.http.HttpStatus.SC_OK) {
                return false;
            }
            client.close();
        } catch (IOException e) {
            return false;
        }
        return true;
    }
}


