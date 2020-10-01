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
import eu.europeana.apikey.keycloak.KeycloakManager;
import eu.europeana.apikey.keycloak.KeycloakSecurityContext;
import eu.europeana.apikey.mail.MailService;
import eu.europeana.apikey.repos.ApiKeyRepo;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    private final KeycloakManager                      keycloakManager;

    @Value("${keycloak.user.admin.username}")
    private String adminUserName;

    @Value("${keycloak.user.admin.password}")
    private String adminUserPassword;

    @Value("${keycloak.user.admin.clientid}")
    private String adminUserClientId;

    @Value("${keycloak.user.admin.granttype}")
    private String adminUserGrantType;


    @Autowired
    private ApiKeyController apikeyController;

    @Autowired
    public UserController(ApiKeyRepo apiKeyRepo,
                          CaptchaManager captchaManager,
                          CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider,
                          MailService emailService,
                          SimpleMailMessage apiKeyCreatedMail,
                          KeycloakManager keycloakManager) {
        this.customKeycloakAuthenticationProvider = customKeycloakAuthenticationProvider;
        this.emailService = emailService;
        this.apiKeyCreatedMail = apiKeyCreatedMail;
        this.keycloakManager = keycloakManager;
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

    @CrossOrigin(maxAge = 600)
    @GetMapping(path = "/{id}", produces = MediaType.TEXT_PLAIN_VALUE)
    public String read(@PathVariable("id") String id) {
        return "Hello there " + id;
    }

    /**
     *
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/{id}")
    public ResponseEntity delete(@PathVariable("id") String id) throws ApiKeyException {
        // retrieve access token for the admin use so we can use that to list and delete the user
        // note that users themselves are not authorised to delete their accounts in Keycloak
        KeycloakAuthenticationToken authenticationToken = (KeycloakAuthenticationToken) customKeycloakAuthenticationProvider
                .authenticate(adminUserName, adminUserPassword, adminUserClientId, adminUserGrantType);
        if (authenticationToken == null) {
            throw new ForbiddenException();
        }
//        KeycloakAuthenticationToken kcAuthToken = apikeyController.checkManagerCredentials();

//        keycloakManager.deleteClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), id);
        return new ResponseEntity(HttpStatus.OK);
    }

//    private ResponseEntity deleteApiKey(ApiKey apiKey, KeycloakAuthenticationToken kcAuthenticationToken) {
//        LOG.warn("User {} is permanently deleting API key {}...",
//                 kcAuthenticationToken.getPrincipal(),
//                 apiKey.getApiKey());
//        this.apiKeyRepo.delete(apiKey);
//        return new ResponseEntity(HttpStatus.NO_CONTENT);
//    }

}


