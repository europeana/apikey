package eu.europeana.apikey.controller;

import eu.europeana.apikey.captcha.CaptchaManager;
import eu.europeana.apikey.exception.*;
import eu.europeana.apikey.keycloak.CustomKeycloakAuthenticationProvider;
import eu.europeana.apikey.keycloak.KeycloakAuthenticationToken;
import eu.europeana.apikey.keycloak.KeycloakManager;
import eu.europeana.apikey.keycloak.KeycloakSecurityContext;
import eu.europeana.apikey.mail.MailService;
import eu.europeana.apikey.repos.ApiKeyRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * Handles incoming requests to delete Keycloak users
 * <p>
 * Created by luthien on 01/10/2020.
 * This controller implements the delete Keycloak user functionality from ticket EA-2234
 */
@RestController
@RequestMapping("/user")
public class UserController {


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

    @CrossOrigin(maxAge = 600)
    @GetMapping(path = "/hello/{id}", produces = MediaType.TEXT_PLAIN_VALUE)
    public String read(@PathVariable("id") String id) {
        return "Hello there " + id;
    }

    /**
     *  retrieve access token for the admin user so we can use that to list & delete the user
     *  because users themselves are not authorised to delete their accounts in Keycloak
     */
    @CrossOrigin(maxAge = 600)
    @DeleteMapping(path = "/delete")
    public String delete(HttpServletRequest request) throws ApiKeyException {

        String userToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        KeycloakAuthenticationToken adminAuthToken = (KeycloakAuthenticationToken) customKeycloakAuthenticationProvider
                .authenticateAdminUser(adminUserName, adminUserPassword, adminUserClientId, adminUserGrantType);

        if (adminAuthToken == null) {
            throw new ForbiddenException();
        }

        String userName = keycloakManager.extractUserName(userToken);

        if (keycloakManager.userExists(userName, (KeycloakSecurityContext) adminAuthToken.getCredentials())){
            return "User " + userName + " exists!";
        }

//        keycloakManager.deleteClient((KeycloakSecurityContext) kcAuthToken.getCredentials(), id);
        return "Blierp.";
//        return new ResponseEntity(HttpStatus.OK);
    }
}


