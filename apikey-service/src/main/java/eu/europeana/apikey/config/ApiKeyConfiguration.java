package eu.europeana.apikey.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Central location where all (or most) configuration settings are loaded.
 */
@Service
public class ApiKeyConfiguration {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.use-resource-role-mappings}")
    private boolean useResourceRoleMappings;

    @Value("${keycloak.realm-public-key}")
    private String realmPublicKey;


    public String getAuthServerUrl() {
        return this.authServerUrl;
    }

    public String getRealm() {
        return this.realm;
    }

    public boolean isUseResourceRoleMappings() {
        return this.useResourceRoleMappings;
    }

    public String getRealmPublicKey() {
        return realmPublicKey;
    }

}
