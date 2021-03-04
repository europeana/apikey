package eu.europeana.apikey.keycloak;

import eu.europeana.api.commons.error.EuropeanaApiException;
import eu.europeana.apikey.TestResources;
import eu.europeana.apikey.config.KeycloakProperties;
import eu.europeana.apikey.domain.ApiKeyRequest;
import eu.europeana.apikey.util.PassGenerator;
import eu.europeana.apikey.domain.ApiKey;
import org.apache.commons.lang3.RandomUtils;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


import static org.mockito.Mockito.*;
import org.mockito.exceptions.misusing.InvalidUseOfMatchersException;

import static eu.europeana.apikey.config.ApikeyDefinitions.CLIENT_DESCRIPTION;

//@RunWith(SpringJUnit4ClassRunner.class)
//@RunWith(SpringRunner.class)
//@SpringBootTest(classes = {KeycloakBuilder.class, KeycloakProperties.class})
//@SpringBootTest(classes = {KeycloakBuilder.class, KeycloakTokenVerifier.class, KeycloakProperties.class})
@RunWith(MockitoJUnitRunner.class)
public class KeycloakClientManagerTest {

    private final PassGenerator pg = new PassGenerator();

    // probably superfluous, just to make sure mockito annotations are initialised
    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }

    @Mock
    private CloseableHttpClient httpClient;

//    @Mock
//    private KeycloakTokenVerifier keycloakTokenVerifier;

    private final KeycloakProperties kcProperties = new KeycloakProperties("https://keycloak-cf-test.eanadev.org/auth",
                                                                           "europeana",
                                                                           true,
                                                                           TestResources.getRealmPublicKey());

//    @InjectMocks
//    private final KeycloakTokenVerifier keycloakTokenVerifier = new KeycloakTokenVerifier(kcProperties);
//    @InjectMocks
//    private final KeycloakClientManager keycloakClientManager = new KeycloakClientManager(kcProperties);
//
//    @Mock
//    Keycloak keycloak;
//
//    @Mock
//    TokenManager tokenManager;
//
//    @Mock
//    KeycloakBuilder keycloakBuilder;
//
//
//    @Mock
//    KeycloakTokenVerifier keycloakTokenVerifier;
//
//    @Mock
//    AccessTokenResponse tokenResponse;

    @Mock
    AccessToken accessToken;

    @InjectMocks
    private final KeycloakClientManager keycloakClientManager = new KeycloakClientManager(TestResources.getKeycloakProperties());

    @InjectMocks
    private KeycloakTokenVerifier keycloakTokenVerifier = new KeycloakTokenVerifier(TestResources.getKeycloakProperties());

//    @Test
    public void authenticateClient() throws VerificationException {

        KeycloakBuilder keycloakBuilder = Mockito.mock(KeycloakBuilder.class);
        try (MockedStatic<KeycloakBuilder> kcb = mockStatic(KeycloakBuilder.class)) {
            kcb.when(KeycloakBuilder::builder).thenReturn(keycloakBuilder);


            Mockito.when(keycloakBuilder.realm(Mockito.anyString())).thenReturn(keycloakBuilder);
            Mockito.when(keycloakBuilder.serverUrl(Mockito.anyString())).thenReturn(keycloakBuilder);
            Mockito.when(keycloakBuilder.clientId(Mockito.anyString())).thenReturn(keycloakBuilder);
            Mockito.when(keycloakBuilder.clientSecret(Mockito.anyString())).thenReturn(keycloakBuilder);
            Mockito.when(keycloakBuilder.grantType(Mockito.anyString())).thenReturn(keycloakBuilder);
            Keycloak keycloak = Mockito.mock(Keycloak.class);
            Mockito.when(keycloakBuilder.build()).thenReturn(keycloak);
            TokenManager tokenManager = Mockito.mock(TokenManager.class);
            Mockito.when(keycloak.tokenManager()).thenReturn(tokenManager);
            AccessTokenResponse tokenResponse = Mockito.mock(AccessTokenResponse.class);
            Mockito.when(tokenManager.getAccessToken()).thenReturn(tokenResponse);
            Mockito.when(tokenResponse.getToken()).thenReturn(TestResources.getCaptchaToken());

    //        Mockito.when(KeycloakTokenVerifier.verifyToken(Mockito.anyString())).thenReturn(accessToken);

            KeycloakPrincipal<KeycloakSecurityContext> principal = keycloakClientManager.authenticateClient(TestResources.getClientId(), TestResources.getClientSecret());

            Assert.assertNotNull(principal);
            Assert.assertNotNull(principal.getKeycloakSecurityContext());
            Assert.assertEquals(accessToken, principal.getKeycloakSecurityContext().getAccessToken());
            Assert.assertEquals(TestResources.getCaptchaToken(), principal.getKeycloakSecurityContext().getAccessTokenString());
        }
    }


//    @Test(timeout = 2000)
    public void createClient() throws EuropeanaApiException, IOException {
        ApiKeyRequest           apiKeyCreate    = prepareApiKeyCreate();
        KeycloakSecurityContext securityContext = prepareForCreateClient();
        String               publicKey       = pg.generate(RandomUtils.nextInt(8, 13));
        ApiKey newKey  = new ApiKey(publicKey,
                                    apiKeyCreate.getFirstName(),
                                    apiKeyCreate.getLastName(),
                                    apiKeyCreate.getEmail(),
                                    apiKeyCreate.getAppName(),
                                    apiKeyCreate.getCompany());
        ClientRepresentation newClientRep = keycloakClientManager.createClient(securityContext, newKey);

        Assert.assertNotNull(publicKey);
        Assert.assertEquals(String.format(CLIENT_DESCRIPTION,
                      apiKeyCreate.getFirstName(),
                      apiKeyCreate.getLastName(),
                      apiKeyCreate.getEmail()), newClientRep.getDescription());
        Assert.assertEquals(TestResources.getNewClientSecret(), newClientRep.getSecret());
    }

    private KeycloakSecurityContext prepareForCreateClient() throws IOException {
        KeycloakSecurityContext securityContext = Mockito.mock(KeycloakSecurityContext.class);
        Mockito.when(securityContext.getAccessTokenString()).thenReturn("TEST");

        // check if apikey already exists
        CloseableHttpResponse getResponse   = Mockito.mock(CloseableHttpResponse.class);
        StatusLine            getStatusLine = Mockito.mock(StatusLine.class);
        Mockito.when(getResponse.getStatusLine()).thenReturn(getStatusLine);
        Mockito.when(getStatusLine.getStatusCode()).thenReturn(200);
        HttpEntity getEntity = Mockito.mock(HttpEntity.class);

        // post new client data
        CloseableHttpResponse postResponse   = Mockito.mock(CloseableHttpResponse.class);
        StatusLine            postStatusLine = Mockito.mock(StatusLine.class);
        Mockito.when(postResponse.getStatusLine()).thenReturn(postStatusLine);
        Mockito.when(postStatusLine.getStatusCode()).thenReturn(201);
        Mockito.when(getResponse.getEntity()).thenReturn(getEntity);
        Mockito.when(getEntity.getContent())
               .thenReturn(new ByteArrayInputStream(TestResources.getEmptyClientRepresentations().getBytes(StandardCharsets.UTF_8)));

        CloseableHttpResponse secondGetResponse   = Mockito.mock(CloseableHttpResponse.class);
        StatusLine            secondGetStatusLine = Mockito.mock(StatusLine.class);
        Mockito.when(secondGetResponse.getStatusLine()).thenReturn(secondGetStatusLine);
        Mockito.when(secondGetStatusLine.getStatusCode()).thenReturn(200);
        HttpEntity secondGetEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(secondGetResponse.getEntity()).thenReturn(secondGetEntity);
        Mockito.when(secondGetEntity.getContent())
               .thenReturn(new ByteArrayInputStream(TestResources.getClientRepresentations().getBytes(StandardCharsets.UTF_8)));

        CloseableHttpResponse secretGetResponse   = Mockito.mock(CloseableHttpResponse.class);
        StatusLine            secretGetStatusLine = Mockito.mock(StatusLine.class);
        Mockito.when(secretGetResponse.getStatusLine()).thenReturn(secretGetStatusLine);
        Mockito.when(secretGetStatusLine.getStatusCode()).thenReturn(200);
        HttpEntity secretGetEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(secretGetResponse.getEntity()).thenReturn(secretGetEntity);
        Mockito.when(secretGetEntity.getContent())
               .thenReturn(new ByteArrayInputStream(TestResources.getCredentialRepresentation().getBytes(StandardCharsets.UTF_8)));

        Mockito.when(httpClient.execute(Mockito.anyObject())).thenAnswer(invocation -> {
            Object argument = invocation.getArguments()[0];
            if (argument instanceof HttpGet) {
                return getResponse;
            }
            throw new InvalidUseOfMatchersException(String.format("Argument %s does not match", argument));
        }).thenAnswer(invocation -> {
            Object argument = invocation.getArguments()[0];
            if (argument instanceof HttpGet) {
                if (((HttpGet) argument).getURI().toString().endsWith("client-secret")) {
                    return secretGetResponse;
                } else {
                    return secondGetResponse;
                }
            } else if (argument instanceof HttpPost) {
                return postResponse;
            }
            throw new InvalidUseOfMatchersException(String.format("Argument %s does not match", argument));
        });
        return securityContext;
    }

    private ApiKeyRequest prepareApiKeyCreate() {
        return new ApiKeyRequest(TestResources.getFirstName(), TestResources.getLastName(), TestResources.getEmail(), TestResources.getAppName(), TestResources.getCompany());
    }

    private AccessToken prepareVerifier() throws VerificationException {
//        KeycloakTokenVerifier verifier = new KeycloakTokenVerifier(null);
        KeycloakTokenVerifier verifier = new KeycloakTokenVerifier(TestResources.getRealmPublicKey());
//        ReflectionTestUtils.setField(verifier, "realmPublicKey", REALM_PUBLIC_KEY);
//        ReflectionTestUtils.invokeMethod(verifier, "init");
        return keycloakTokenVerifier.verifyToken(TestResources.getToken());
    }

//    @Test
    public void getAuthoritiesForRealm() throws VerificationException {
        AccessToken                  accessToken         = prepareVerifier();
        List<String>                 roles               = prepareRoles(false);
        Collection<GrantedAuthority> authorityCollection = keycloakClientManager.getAuthorities(accessToken);

        Assert.assertNotNull(authorityCollection);
        Assert.assertFalse(authorityCollection.isEmpty());
        authorityCollection.forEach(grantedAuthority -> {
            Assert.assertTrue(roles.contains(grantedAuthority.getAuthority()));
        });
    }

//    @Test
    public void getAuthoritiesForResource() throws VerificationException {
        AccessToken                  accessToken         = prepareVerifier();
        List<String>                 roles               = prepareRoles(true);
        Collection<GrantedAuthority> authorityCollection = keycloakClientManager.getAuthorities(accessToken);

        Assert.assertNotNull(authorityCollection);
        Assert.assertFalse(authorityCollection.isEmpty());
        authorityCollection.forEach(grantedAuthority -> {
            Assert.assertTrue(roles.contains(grantedAuthority.getAuthority()));
        });
    }

    private List<String> prepareRoles(boolean useResourceRoleMappings) {
        List<String> roles = new ArrayList<>();
        if (useResourceRoleMappings) {
            ReflectionTestUtils.setField(keycloakClientManager, "useResourceRoleMappings", true);
            roles.add("uma_protection");
            roles.add("view-realm");
            roles.add("view-identity-providers");
            roles.add("manage-identity-providers");
            roles.add("impersonation");
            roles.add("realm-admin");
            roles.add("create-client");
            roles.add("manage-users");
            roles.add("query-realms");
            roles.add("view-authorization");
            roles.add("query-clients");
            roles.add("query-users");
            roles.add("manage-events");
            roles.add("manage-realm");
            roles.add("view-events");
            roles.add("view-users");
            roles.add("view-clients");
            roles.add("manage-authorization");
            roles.add("manage-clients");
            roles.add("query-groups");
        } else {
            roles.add("API");
        }
        return roles;
    }

    @Test
    public void isOwnerWhenOwner() {
        KeycloakAuthenticationToken keycloakAuthenticationToken = Mockito.mock(KeycloakAuthenticationToken.class);
        KeycloakSecurityContext     securityContext             = Mockito.mock(KeycloakSecurityContext.class);
        Mockito.when(keycloakAuthenticationToken.getName()).thenReturn(TestResources.getClientId());
        Mockito.when(keycloakAuthenticationToken.getCredentials()).thenReturn(securityContext);

        boolean authorized = keycloakClientManager.isOwner(TestResources.getClientId(), keycloakAuthenticationToken);

        Assert.assertTrue(authorized);
    }

    @Test
    public void isOwnerWhenOther() {
        KeycloakAuthenticationToken keycloakAuthenticationToken = Mockito.mock(KeycloakAuthenticationToken.class);
        KeycloakSecurityContext     securityContext             = Mockito.mock(KeycloakSecurityContext.class);
        Mockito.when(keycloakAuthenticationToken.getName()).thenReturn(TestResources.getClientId());
        Mockito.when(keycloakAuthenticationToken.getCredentials()).thenReturn(securityContext);

        boolean authorized = keycloakClientManager.isOwner("other key", keycloakAuthenticationToken);

        Assert.assertFalse(authorized);
    }

//    @Test
    public void isClientAuthorizedWhenManager() throws VerificationException {
        KeycloakAuthenticationToken keycloakAuthenticationToken = Mockito.mock(KeycloakAuthenticationToken.class);
        KeycloakSecurityContext     securityContext             = Mockito.mock(KeycloakSecurityContext.class);
        AccessToken                 accessToken                 = prepareVerifier();
        prepareRoles(true);
        Collection<GrantedAuthority> authorityCollection = keycloakClientManager.getAuthorities(accessToken);
        Mockito.when(keycloakAuthenticationToken.getAuthorities()).thenReturn(authorityCollection);
        Mockito.when(keycloakAuthenticationToken.getName()).thenReturn("manager");
        Mockito.when(keycloakAuthenticationToken.getCredentials()).thenReturn(securityContext);

        boolean authorized = keycloakClientManager.isManagerClientAuthorized(keycloakAuthenticationToken);

        Assert.assertTrue(authorized);
    }

    @Test
    public void isClientAuthorizedWhenOther() {
        KeycloakAuthenticationToken keycloakAuthenticationToken = Mockito.mock(KeycloakAuthenticationToken.class);
        KeycloakSecurityContext     securityContext             = Mockito.mock(KeycloakSecurityContext.class);
        Mockito.when(keycloakAuthenticationToken.getCredentials()).thenReturn(securityContext);

        boolean authorized = keycloakClientManager.isManagerClientAuthorized(keycloakAuthenticationToken);

        Assert.assertFalse(authorized);
    }

    @Test(expected = EuropeanaApiException.class)
    public void updateClientWhenClientMissing() throws IOException, EuropeanaApiException {
        ApiKeyRequest           apiKeyDetails   = prepareApiKeyUpdate();
        KeycloakSecurityContext securityContext = prepareForUpdateClient(false, true);

        keycloakClientManager.updateClient(securityContext, apiKeyDetails, TestResources.getClientId());
    }

    @Test
    public void updateClientWhenClientExists() throws IOException, EuropeanaApiException {
        ApiKeyRequest           apiKeyUpdate    = prepareApiKeyUpdate();
        KeycloakSecurityContext securityContext = prepareForUpdateClient(true, true);

        keycloakClientManager.updateClient(securityContext, apiKeyUpdate, TestResources.getClientId());
    }

    private KeycloakSecurityContext prepareForUpdateClient(boolean existing, boolean enabled) throws IOException {
        KeycloakSecurityContext securityContext = Mockito.mock(KeycloakSecurityContext.class);
        Mockito.when(securityContext.getAccessTokenString()).thenReturn("TEST");

        CloseableHttpResponse putResponse   = Mockito.mock(CloseableHttpResponse.class);
        StatusLine            putStatusLine = Mockito.mock(StatusLine.class);
        Mockito.when(putResponse.getStatusLine()).thenReturn(putStatusLine);
        Mockito.when(putStatusLine.getStatusCode()).thenReturn(204);

        CloseableHttpResponse getResponse   = Mockito.mock(CloseableHttpResponse.class);
        StatusLine            getStatusLine = Mockito.mock(StatusLine.class);
        Mockito.when(getResponse.getStatusLine()).thenReturn(getStatusLine);
        Mockito.when(getStatusLine.getStatusCode()).thenReturn(200);
        HttpEntity getEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(getResponse.getEntity()).thenReturn(getEntity);
        if (existing) {
            if (enabled) {
                Mockito.when(getEntity.getContent())
                       .thenReturn(new ByteArrayInputStream(TestResources.getClientRepresentations().getBytes(StandardCharsets.UTF_8)));
            } else {
                Mockito.when(getEntity.getContent())
                       .thenReturn(new ByteArrayInputStream(TestResources.getDisabledClientRepresentations().getBytes(StandardCharsets.UTF_8)));
            }
        } else {
            Mockito.when(getEntity.getContent())
                   .thenReturn(new ByteArrayInputStream(TestResources.getEmptyClientRepresentations().getBytes(StandardCharsets.UTF_8)));
        }

        Mockito.when(httpClient.execute(Mockito.anyObject())).thenAnswer(invocation -> {
            Object argument = invocation.getArguments()[0];
            if (argument instanceof HttpGet) {
                return getResponse;
            }
            throw new InvalidUseOfMatchersException(String.format("Argument %s does not match", argument));
        }).thenAnswer(invocation -> {
            Object argument = invocation.getArguments()[0];
            if (argument instanceof HttpPut) {
                return putResponse;
            }
            throw new InvalidUseOfMatchersException(String.format("Argument %s does not match", argument));
        });
        return securityContext;
    }

    private ApiKeyRequest prepareApiKeyUpdate() {
        return new ApiKeyRequest(TestResources.getFirstName(), TestResources.getLastName(), TestResources.getEmail(), TestResources.getAppName(), TestResources.getCompany(), TestResources.getSector(), TestResources.getWebsite());
    }

    @Test(expected = EuropeanaApiException.class)
    public void invalidateClientWhenClientMissing() throws IOException, EuropeanaApiException {
        KeycloakSecurityContext securityContext = prepareForUpdateClient(false, true);
        keycloakClientManager.disableClient(TestResources.getClientId(), securityContext);
    }

    @Test
    public void invalidateClientWhenClientExists() throws IOException, EuropeanaApiException {
        KeycloakSecurityContext securityContext = prepareForUpdateClient(true, true);
        keycloakClientManager.disableClient(TestResources.getClientId(), securityContext);
    }

    @Test(expected = EuropeanaApiException.class)
    public void reenableClientWhenClientMissing() throws IOException, EuropeanaApiException {
        KeycloakSecurityContext securityContext = prepareForUpdateClient(false, true);
        keycloakClientManager.enableClient(TestResources.getClientId(), securityContext);
    }

    @Test
    public void reenableClientWhenClientExists() throws IOException, EuropeanaApiException {
        KeycloakSecurityContext securityContext = prepareForUpdateClient(true, false);
        keycloakClientManager.enableClient(TestResources.getClientId(), securityContext);
    }

}