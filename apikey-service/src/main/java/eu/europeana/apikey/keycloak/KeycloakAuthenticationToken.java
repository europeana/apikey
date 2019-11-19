package eu.europeana.apikey.keycloak;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.security.Principal;
import java.util.Collection;

public class KeycloakAuthenticationToken
        extends AbstractAuthenticationToken
        implements Authentication {

    private Principal principal;

    public KeycloakAuthenticationToken(KeycloakPrincipal<KeycloakSecurityContext> principal) {
        super((Collection) null);
        this.principal = principal;
    }

    KeycloakAuthenticationToken(KeycloakPrincipal<KeycloakSecurityContext> keycloakPrincipal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = keycloakPrincipal;
        setAuthenticated(true);
        setDetails(keycloakPrincipal.getName());
    }

    @Override
    public Object getCredentials() {
        return ((KeycloakPrincipal) principal).getKeycloakSecurityContext();
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
