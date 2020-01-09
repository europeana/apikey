package eu.europeana.apikey.keycloak;

import org.keycloak.adapters.springsecurity.KeycloakAuthenticationException;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;

import java.io.Serializable;

public class KeycloakSecurityContext implements Serializable {

    private static final long serialVersionUID = 6611924880256064860L;

    private transient Keycloak              keycloak;
    private transient AccessToken           accessToken;
    private transient KeycloakTokenVerifier keycloakTokenVerifier;

    private String accessTokenString;

    KeycloakSecurityContext(Keycloak keycloak,
                            AccessToken accessToken,
                            String accessTokenString,
                            KeycloakTokenVerifier keycloakTokenVerifier) {
        this.keycloak              = keycloak;
        this.accessToken           = accessToken;
        this.accessTokenString     = accessTokenString;
        this.keycloakTokenVerifier = keycloakTokenVerifier;
    }

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

    String getAccessTokenString() {
        refreshToken();
        return accessTokenString;
    }
}
