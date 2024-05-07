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
@PropertySource(value = "classpath:apikey.user.properties", ignoreResourceNotFound = true)
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {

    private String  authServerUrl;
    private String  realm;
    private boolean useResourceRoleMappings;
    private String  realmPublicKey;
    private String  masterPublicKey;

    /**
     * Instantiates a new Keycloak properties.
     */
    public KeycloakProperties() {
    }

    /**
     * Instantiates a new Keycloak properties.
     *
     * @param authServerUrl           the auth server url
     * @param realm                   the realm
     * @param useResourceRoleMappings the use resource role mappings
     * @param realmPublicKey          the realm public key
     */
    public KeycloakProperties(String authServerUrl,
                              String realm,
                              boolean useResourceRoleMappings,
                              String realmPublicKey) {
        this.authServerUrl = authServerUrl;
        this.realm = realm;
        this.useResourceRoleMappings = useResourceRoleMappings;
        this.realmPublicKey = realmPublicKey;
    }

    @PostConstruct()
    private void logImportantSettings() {
        LogManager.getLogger(KeycloakProperties.class).info("Keycloak server {}, realm {}", authServerUrl, realm);
    }


    /**
     * Gets auth server url.
     *
     * @return the auth server url
     */
    public String getAuthServerUrl() {
        return authServerUrl;
    }

    /**
     * Sets auth server url.
     *
     * @param authServerUrl the auth server url
     */
    public void setAuthServerUrl(String authServerUrl) {
        this.authServerUrl = authServerUrl;
    }

    /**
     * Gets realm.
     *
     * @return the realm
     */
    public String getRealm() {
        return realm;
    }

    /**
     * Sets realm.
     *
     * @param realm the realm
     */
    public void setRealm(String realm) {
        this.realm = realm;
    }

    /**
     * Is use resource role mappings boolean.
     *
     * @return the boolean
     */
    public boolean isUseResourceRoleMappings() {
        return useResourceRoleMappings;
    }

    /**
     * Sets use resource role mappings.
     *
     * @param useResourceRoleMappings the use resource role mappings
     */
    public void setUseResourceRoleMappings(boolean useResourceRoleMappings) {
        this.useResourceRoleMappings = useResourceRoleMappings;
    }

    /**
     * Gets realm public key.
     *
     * @return the realm public key
     */
    public String getRealmPublicKey() {
        return realmPublicKey;
    }

    /**
     * Sets realm public key.
     *
     * @param realmPublicKey the realm public key
     */
    public void setRealmPublicKey(String realmPublicKey) {
        this.realmPublicKey = realmPublicKey;
    }

    /**
     * Gets master public key.
     *
     * @return the master public key
     */
    public String getMasterPublicKey() {
        return masterPublicKey;
    }

    /**
     * Sets master public key.
     *
     * @param masterPublicKey the master public key
     */
    public void setMasterPublicKey(String masterPublicKey) {
        this.masterPublicKey = masterPublicKey;
    }
}
