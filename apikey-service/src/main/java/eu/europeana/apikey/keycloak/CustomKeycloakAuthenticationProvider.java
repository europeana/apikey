package eu.europeana.apikey.keycloak;

import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Authentication provider used to authenticate clients following the client credentials grant type
 */
public class CustomKeycloakAuthenticationProvider extends KeycloakAuthenticationProvider {
    private KeycloakManager keycloakManager;

    public CustomKeycloakAuthenticationProvider(KeycloakManager keycloakManager) {
        this.keycloakManager = keycloakManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        String clientId = authentication.getName();
        String clientSecret = authentication.getCredentials().toString();

        KeycloakSecurityContext securityContext = keycloakManager.authenticateClient(clientId, clientSecret);

        if (securityContext != null) {
            return new KeycloakAuthenticationToken(clientId, securityContext, keycloakManager.getAuthorities(securityContext.getAccessToken()));
        }

        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}
