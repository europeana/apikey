package eu.europeana.apikey.keycloak;

import eu.europeana.apikey.exception.ForbiddenException;
import eu.europeana.apikey.exception.KCAuthException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/**
 * Authentication provider used to authenticate clients following the client credentials grant type
 */
@Service
public class CustomKeycloakAuthenticationProvider extends KeycloakAuthenticationProvider {

    private static final Logger LOG = LogManager.getLogger(CustomKeycloakAuthenticationProvider.class);

    private final KeycloakClientManager keycloakClientManager;
    private final KeycloakUserManager   keycloakUserManager;

    public CustomKeycloakAuthenticationProvider(KeycloakClientManager keycloakClientManager,
                                                KeycloakUserManager keycloakUserManager) {
        this.keycloakClientManager = keycloakClientManager;
        this.keycloakUserManager = keycloakUserManager;
    }
    // rename to client
    public Authentication authenticateAdminUser(String clientId, String clientSecret) {
        LOG.debug("Authenticating client {}", clientId);
        KeycloakPrincipal<KeycloakSecurityContext> principal = keycloakClientManager.authenticateClient(clientId,
                                                                                                        clientSecret);
        if (principal != null) {
            return new KeycloakAuthenticationToken(principal,
                                                   keycloakClientManager.getAuthorities(principal.getKeycloakSecurityContext()
                                                                                                 .getAccessToken()));
        }
        LOG.info("Authentication for client {} failed!", clientId);
        return null;
    }

    // this is for the admin user authentication
    public Authentication authenticateAdminUser(String username,
                                                String password,
                                                String clientId,
                                                String grantType) throws KCAuthException {
        LOG.debug("Authenticating user {}", username);
        KeycloakPrincipal<KeycloakSecurityContext> principal;
        try {
            principal = keycloakUserManager.authenticateAdminUser(username, password, clientId, grantType);
        } catch (Exception e) {
            throw new KCAuthException(e.getMessage(), null == e.getCause() ? "N/A" : e.getCause().getMessage());
        }
        if (principal != null) {
            return new KeycloakAuthenticationToken(principal,
                                                   keycloakClientManager.getAuthorities(principal.getKeycloakSecurityContext()
                                                                                                 .getAccessToken()));
        }
        LOG.info("Authentication for user {} failed!", username);
        return null;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        return authenticateAdminUser(authentication.getName(), authentication.getCredentials().toString());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}
