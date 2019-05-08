package eu.europeana.apikey.keycloak;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class KeycloakAuthenticationToken
        extends AbstractAuthenticationToken
        implements Authentication {

    private String clientId;

    private KeycloakSecurityContext securityContext;

    public KeycloakAuthenticationToken(String clientId) {
        super((Collection) null);
        this.clientId = clientId;
    }

    KeycloakAuthenticationToken(String clientId, KeycloakSecurityContext securityContext, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.clientId = clientId;
        this.securityContext = securityContext;
        setAuthenticated(true);
        setDetails(securityContext);
    }

    @Override
    public Object getCredentials() {
        return securityContext;
    }

    @Override
    public Object getPrincipal() {
        return clientId;
    }
}
