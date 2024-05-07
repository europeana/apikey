package eu.europeana.apikey.keycloak;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.security.Principal;
import java.util.Collection;

/**
 * The type Keycloak authentication token.
 */
public final class KeycloakAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 6378042438184913288L;

    private final transient Principal principal;


    /**
     * Instantiates a new Keycloak authentication token.
     *
     * @param principal the principal
     */
    public KeycloakAuthenticationToken(KeycloakPrincipal<KeycloakSecurityContext> principal) {
        super(null);
        this.principal = principal;
    }

    /**
     * Instantiates a new Keycloak authentication token.
     *
     * @param keycloakPrincipal the keycloak principal
     * @param authorities       the authorities
     */
    public KeycloakAuthenticationToken(
            KeycloakPrincipal<KeycloakSecurityContext> keycloakPrincipal,
            Collection<? extends GrantedAuthority> authorities) {
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
