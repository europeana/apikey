package eu.europeana.apikey.keycloak;

import org.keycloak.adapters.springsecurity.KeycloakAuthenticationException;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;

import java.io.Serializable;

/**
 * The type Keycloak security context.
 */
public class KeycloakSecurityContext implements Serializable {

    private static final long serialVersionUID = 6611924880256064860L;

    private final transient Keycloak    keycloak;
    private transient       AccessToken           accessToken;
    private final transient KeycloakTokenVerifier keycloakTokenVerifier;

    /**
     * Just to satisfy the unreasonable demands of the Maven javadoc checker
     */
    private String accessTokenString;

    /**
     * Instantiates a new Keycloak security context.
     *
     * @param keycloak              the keycloak
     * @param accessToken           the access token
     * @param accessTokenString     the access token string
     * @param keycloakTokenVerifier the keycloak token verifier
     */
    KeycloakSecurityContext(Keycloak keycloak,
                            AccessToken accessToken,
                            String accessTokenString,
                            KeycloakTokenVerifier keycloakTokenVerifier) {
        this.keycloak              = keycloak;
        this.accessToken           = accessToken;
        this.accessTokenString     = accessTokenString;
        this.keycloakTokenVerifier = keycloakTokenVerifier;
    }

    /**
     * Gets access token.
     *
     * @return the access token
     */
    AccessToken getAccessToken() {
        refreshToken();
        return accessToken;
    }

    private void refreshToken() {
        if (accessToken.isExpired()) {
            try {
                accessToken       = keycloakTokenVerifier.verifyToken(keycloak.tokenManager()
                                                                              .getAccessToken()
                                                                              .getToken());
                accessTokenString = keycloak.tokenManager().getAccessToken().getToken();
            } catch (VerificationException e) {
                throw new KeycloakAuthenticationException("Access token verification failed...", e);
            }
        }
    }

    /**
     * Gets access token string.
     *
     * @return the access token string
     */
    String getAccessTokenString() {
        refreshToken();
        return accessTokenString;
    }
}
