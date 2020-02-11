package eu.europeana.apikey.config;

import org.apache.logging.log4j.LogManager;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * Central location where all (or most) configuration settings are loaded.
 */

@Component
@PropertySource("classpath:apikey.properties")
@PropertySource(value = "classpath:apikey-user.properties", ignoreResourceNotFound = true)
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {

    private String  authServerUrl;
    private String  realm;
    private boolean useResourceRoleMappings;
    private String  realmPublicKey;
    private String  managerClientId;
    private String  managerClientSecret;

    public KeycloakProperties() {
    }

    public KeycloakProperties(String authServerUrl, String realm, boolean useResourceRoleMappings, String realmPublicKey){
        this.authServerUrl = authServerUrl;
        this.realm = realm;
        this.useResourceRoleMappings = useResourceRoleMappings;
        this.realmPublicKey = realmPublicKey;
    }

    @PostConstruct()
    private void logImportantSettings() {
        LogManager.getLogger(KeycloakProperties.class).info("Keycloak server {}, realm {}", authServerUrl, realm);
    }


    public String getAuthServerUrl() {
        return authServerUrl;
    }

    public void setAuthServerUrl(String authServerUrl) {
        this.authServerUrl = authServerUrl;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public boolean isUseResourceRoleMappings() {
        return useResourceRoleMappings;
    }

    public void setUseResourceRoleMappings(boolean useResourceRoleMappings) {
        this.useResourceRoleMappings = useResourceRoleMappings;
    }

    public String getRealmPublicKey() {
        return realmPublicKey;
    }

    public void setRealmPublicKey(String realmPublicKey) {
        this.realmPublicKey = realmPublicKey;
    }

    public String getManagerClientId() {
        return managerClientId;
    }

    public void setManagerClientId(String managerClientId) {
        this.managerClientId = managerClientId;
    }

    public String getManagerClientSecret() {
        return managerClientSecret;
    }

    public void setManagerClientSecret(String managerClientSecret) {
        this.managerClientSecret = managerClientSecret;
    }
}
