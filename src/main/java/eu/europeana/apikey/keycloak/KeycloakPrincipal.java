package eu.europeana.apikey.keycloak;

import java.io.Serializable;
import java.security.Principal;

/**
 * This class implements Principal interface used in Spring security. It holds information on Keycloak clientId that
 * was authorized and KeycloakSecurityContext that contains access tokens.
 *
 * @param <T> KeycloakSecurityContext class used for context field.
 */
public class KeycloakPrincipal<T extends KeycloakSecurityContext> implements Principal, Serializable {

    private static final long serialVersionUID = 6491038532248885544L;

    protected final String name;
    protected final T      context;

    KeycloakPrincipal(String name, T context) {
        this.name    = name;
        this.context = context;
    }

    T getKeycloakSecurityContext() {
        return this.context;
    }

    public String getName() {
        return this.name;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o != null && this.getClass() == o.getClass()) {
            KeycloakPrincipal that = (KeycloakPrincipal) o;
            return this.name.equals(that.name);
        } else {
            return false;
        }
    }

    public int hashCode() {
        return this.name.hashCode();
    }

    public String toString() {
        return this.name;
    }

}
