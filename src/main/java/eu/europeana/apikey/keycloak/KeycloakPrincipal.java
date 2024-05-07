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

    /**
     * The Name.
     */
    protected final String name;
    /**
     * The Context.
     */
    protected final T      context;

    /**
     * Instantiates a new Keycloak principal.
     *
     * @param name    the name
     * @param context the context
     */
    KeycloakPrincipal(String name, T context) {
        this.name    = name;
        this.context = context;
    }

    /**
     * Gets keycloak security context.
     *
     * @return the keycloak security context
     */
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
            KeycloakPrincipal<T> that = (KeycloakPrincipal<T>) o;
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
