package eu.europeana.apikey.keycloak;

import eu.europeana.apikey.TestResources;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class KeycloakSecurityContextTest {
    @Mock
    private Keycloak keycloak;
    @Mock
    private AccessToken accessToken;
    @Mock
    private KeycloakTokenVerifier keycloakTokenVerifier;
    private KeycloakSecurityContext securityContext;

    @Before
    public void prepareForTests() {
        securityContext = new KeycloakSecurityContext(keycloak,
                                                      accessToken,
                                                      TestResources.getCaptchaToken(),
                                                      keycloakTokenVerifier);
    }

//    @Test
    public void getAccessTokenWhenExpired() throws VerificationException {
        AccessToken refreshedToken = prepareForExpired();
        AccessToken token          = securityContext.getAccessToken();
        Assert.assertNotNull(token);
        Assert.assertEquals(refreshedToken, token);
    }

    @Test
    public void getAccessTokenWhenValid() {
        Mockito.when(accessToken.isExpired()).thenReturn(false);
        AccessToken token = securityContext.getAccessToken();
        Assert.assertNotNull(token);
        Assert.assertEquals(accessToken, token);
    }

//    @PrepareForTest(KeycloakTokenVerifier.class)
    @Test
    public void getAccessTokenStringWhenExpired() throws VerificationException {
        prepareForExpired();
        String tokenString = securityContext.getAccessTokenString();
        Assert.assertNotNull(tokenString);
        Assert.assertEquals(TestResources.getAccessTokenStringRefreshed(), tokenString);
    }

    @Test
    public void getAccessTokenStringWhenValid() throws VerificationException {
        Mockito.when(accessToken.isExpired()).thenReturn(false);
        String tokenString = securityContext.getAccessTokenString();
        Assert.assertNotNull(tokenString);
        Assert.assertEquals(TestResources.getCaptchaToken(), tokenString);
    }

    private AccessToken prepareForExpired() throws VerificationException {
        AccessToken refreshedToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.isExpired()).thenReturn(true);
        TokenManager tokenManager = Mockito.mock(TokenManager.class);
        Mockito.when(keycloak.tokenManager()).thenReturn(tokenManager);
        AccessTokenResponse tokenResponse = Mockito.mock(AccessTokenResponse.class);
        Mockito.when(tokenManager.getAccessToken()).thenReturn(tokenResponse);
        Mockito.when(tokenResponse.getToken()).thenReturn(TestResources.getAccessTokenStringRefreshed());
        KeycloakTokenVerifier keycloakTokenVerifier = Mockito.mock(KeycloakTokenVerifier.class);
        return refreshedToken;
    }
}