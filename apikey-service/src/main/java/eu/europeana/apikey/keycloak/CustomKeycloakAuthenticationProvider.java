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

        KeycloakPrincipal<KeycloakSecurityContext> principal = keycloakManager.authenticateClient(clientId, clientSecret);

        if (principal != null) {
            return new KeycloakAuthenticationToken(principal, keycloakManager.getAuthorities(principal.getKeycloakSecurityContext().getAccessToken()));
        }

        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}
