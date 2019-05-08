package eu.europeana.apikey.keycloak;

import org.keycloak.adapters.springsecurity.KeycloakAuthenticationException;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;

import java.io.Serializable;

public class KeycloakSecurityContext implements Serializable {
    private transient Keycloak keycloak;

    private transient AccessToken accessToken;

    private String accessTokenString;

    KeycloakSecurityContext(Keycloak keycloak, AccessToken accessToken, String accessTokenString) {
        this.keycloak = keycloak;
        this.accessToken = accessToken;
        this.accessTokenString = accessTokenString;
    }

    AccessToken getAccessToken() {
        refreshToken();
        return accessToken;
    }

    private void refreshToken() {
        if (accessToken.isExpired()) {
            try {
                accessToken = KeycloakTokenVerifier.verifyToken(keycloak.tokenManager().getAccessToken().getToken());
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
