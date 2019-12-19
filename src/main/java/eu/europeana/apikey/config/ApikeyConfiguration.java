package eu.europeana.apikey.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

/**
 * Central location where all (or most) configuration settings are loaded.
 */

// TODO I think we don't need this, it's easier to just inject the properties directly where needed

@Configuration
@Component
//@PropertySource(value = "classpath:application.properties", ignoreResourceNotFound = true)
@PropertySource(value = "classpath:application-user.properties", ignoreResourceNotFound = true)
public class ApikeyConfiguration {

    private final String authServerUrl;
    private final String realm;
    private final boolean useResourceRoleMappings;
    private final String realmPublicKey;

    @Autowired
    public ApikeyConfiguration(@Value("${keycloak.auth-server-url}") String authServerUrl,
                               @Value("${keycloak.realm}") String realm,
                               @Value("${keycloak.use-resource-role-mappings}") boolean useResourceRoleMappings,
                               @Value("${keycloak.realm-public-key}") String realmPublicKey) {
        this.authServerUrl = authServerUrl;
        this.realm = realm;
        this.useResourceRoleMappings = useResourceRoleMappings;
        this.realmPublicKey = realmPublicKey;
    }

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
