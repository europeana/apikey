package eu.europeana.apikey.keycloak;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
//import org.junit.runners.JUnit4;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.boot.test.context.SpringBootTest;

@RunWith(PowerMockRunner.class)
@PrepareForTest(KeycloakTokenVerifier.class)
@SpringBootTest(classes = {KeycloakTokenVerifier.class})
public class KeycloakSecurityContextTest {

    @Mock
    private Keycloak keycloak;

    @Mock
    private AccessToken accessToken;

    private static final String ACCESS_TOKEN_STRING = "token1";
    private static final String ACCESS_TOKEN_STRING_REFRESHED = "token2";

    private KeycloakSecurityContext securityContext;

    @Before
    public void prepareForTests() {
        securityContext = new KeycloakSecurityContext(keycloak, accessToken, ACCESS_TOKEN_STRING);
    }

    @Test
    public void getAccessTokenWhenExpired() throws VerificationException {
        AccessToken refreshedToken = prepareForExpired();
        AccessToken token = securityContext.getAccessToken();
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

    @Test
    public void getAccessTokenStringWhenExpired() throws VerificationException {
        prepareForExpired();
        String tokenString = securityContext.getAccessTokenString();
        Assert.assertNotNull(tokenString);
        Assert.assertEquals(ACCESS_TOKEN_STRING_REFRESHED, tokenString);
    }

    @Test
    public void getAccessTokenStringWhenValid() throws VerificationException {
        Mockito.when(accessToken.isExpired()).thenReturn(false);
        String tokenString = securityContext.getAccessTokenString();
        Assert.assertNotNull(tokenString);
        Assert.assertEquals(ACCESS_TOKEN_STRING, tokenString);
    }

    private AccessToken prepareForExpired() throws VerificationException {
        AccessToken refreshedToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.isExpired()).thenReturn(true);
        TokenManager tokenManager = Mockito.mock(TokenManager.class);
        Mockito.when(keycloak.tokenManager()).thenReturn(tokenManager);
        AccessTokenResponse tokenResponse = Mockito.mock(AccessTokenResponse.class);
        Mockito.when(tokenManager.getAccessToken()).thenReturn(tokenResponse);
        Mockito.when(tokenResponse.getToken()).thenReturn(ACCESS_TOKEN_STRING_REFRESHED);
        PowerMockito.mockStatic(KeycloakTokenVerifier.class);
        Mockito.when(KeycloakTokenVerifier.verifyToken(Mockito.anyString())).thenReturn(refreshedToken);
        return refreshedToken;
    }
}