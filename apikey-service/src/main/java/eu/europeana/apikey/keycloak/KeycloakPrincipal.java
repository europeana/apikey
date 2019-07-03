package eu.europeana.apikey.keycloak;

import java.io.Serializable;
import java.security.Principal;

public class KeycloakPrincipal<T extends KeycloakSecurityContext>
        implements Principal, Serializable {

    protected final String name;

    protected final T context;

    public KeycloakPrincipal(String name, T context) {
        this.name = name;
        this.context = context;
    }

    public T getKeycloakSecurityContext() {
        return this.context;
    }

    public String getName() {
        return this.name;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o != null && this.getClass() == o.getClass()) {
            KeycloakPrincipal that = (KeycloakPrincipal)o;
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
