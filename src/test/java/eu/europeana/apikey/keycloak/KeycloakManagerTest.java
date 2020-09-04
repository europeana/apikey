package eu.europeana.apikey.keycloak;

import eu.europeana.apikey.config.KeycloakProperties;
import eu.europeana.apikey.domain.ApiKeyRequest;
import eu.europeana.apikey.domain.ApiKeySecret;
import eu.europeana.apikey.exception.ApiKeyException;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.exceptions.misusing.InvalidUseOfMatchersException;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"javax.*", "com.sun.org.apache.xerces.*", "org.xml.*", "org.w3c.dom.*"})
@SpringBootTest(classes = {KeycloakBuilder.class, KeycloakTokenVerifier.class, KeycloakProperties.class})
public class KeycloakManagerTest {


    private static final String CREDENTIAL_REPRESENTATION = "{\n" +
            "    \"type\": \"secret\",\n" +
            "    \"value\": \"134d4ec9-a26e-4dcb-93b7-13e22606eb9d\"\n" +
            "}";


    private static final String DISABLED_CLIENT_REPRESENTATIONS  = "[\n" +
            "    {\n" +
            "        \"id\": \"fff0fb90-739d-448e-b511-3738af0a2355\",\n" +
            "        \"clientId\": \"test-add-rest\",\n" +
            "        \"surrogateAuthRequired\": false,\n" +
            "        \"enabled\": false,\n" +
            "        \"clientAuthenticatorType\": \"client-secret\",\n" +
            "        \"redirectUris\": [],\n" +
            "        \"webOrigins\": [],\n" +
            "        \"notBefore\": 0,\n" +
            "        \"bearerOnly\": false,\n" +
            "        \"consentRequired\": false,\n" +
            "        \"standardFlowEnabled\": true,\n" +
            "        \"implicitFlowEnabled\": false,\n" +
            "        \"directAccessGrantsEnabled\": false,\n" +
            "        \"serviceAccountsEnabled\": false,\n" +
            "        \"publicClient\": false,\n" +
            "        \"frontchannelLogout\": false,\n" +
            "        \"protocol\": \"openid-connect\",\n" +
            "        \"attributes\": {},\n" +
            "        \"authenticationFlowBindingOverrides\": {},\n" +
            "        \"fullScopeAllowed\": true,\n" +
            "        \"nodeReRegistrationTimeout\": -1,\n" +
            "        \"defaultClientScopes\": [\n" +
            "            \"web-origins\",\n" +
            "            \"role_list\",\n" +
            "            \"profile\",\n" +
            "            \"roles\",\n" +
            "            \"email\"\n" +
            "        ],\n" +
            "        \"optionalClientScopes\": [\n" +
            "            \"address\",\n" +
            "            \"phone\",\n" +
            "            \"offline_access\"\n" +
            "        ],\n" +
            "        \"access\": {\n" +
            "            \"view\": true,\n" +
            "            \"configure\": true,\n" +
            "            \"manage\": true\n" +
            "        }\n" +
            "    }\n" +
            "]";

    private static final String CLIENT_REPRESENTATIONS = "[\n" +
            "    {\n" +
            "        \"id\": \"fff0fb90-739d-448e-b511-3738af0a2355\",\n" +
            "        \"clientId\": \"test-add-rest\",\n" +
            "        \"surrogateAuthRequired\": false,\n" +
            "        \"enabled\": true,\n" +
            "        \"clientAuthenticatorType\": \"client-secret\",\n" +
            "        \"redirectUris\": [],\n" +
            "        \"webOrigins\": [],\n" +
            "        \"notBefore\": 0,\n" +
            "        \"bearerOnly\": false,\n" +
            "        \"consentRequired\": false,\n" +
            "        \"standardFlowEnabled\": true,\n" +
            "        \"implicitFlowEnabled\": false,\n" +
            "        \"directAccessGrantsEnabled\": false,\n" +
            "        \"serviceAccountsEnabled\": false,\n" +
            "        \"publicClient\": false,\n" +
            "        \"frontchannelLogout\": false,\n" +
            "        \"protocol\": \"openid-connect\",\n" +
            "        \"attributes\": {},\n" +
            "        \"authenticationFlowBindingOverrides\": {},\n" +
            "        \"fullScopeAllowed\": true,\n" +
            "        \"nodeReRegistrationTimeout\": -1,\n" +
            "        \"defaultClientScopes\": [\n" +
            "            \"web-origins\",\n" +
            "            \"role_list\",\n" +
            "            \"profile\",\n" +
            "            \"roles\",\n" +
            "            \"email\"\n" +
            "        ],\n" +
            "        \"optionalClientScopes\": [\n" +
            "            \"address\",\n" +
            "            \"phone\",\n" +
            "            \"offline_access\"\n" +
            "        ],\n" +
            "        \"access\": {\n" +
            "            \"view\": true,\n" +
            "            \"configure\": true,\n" +
            "            \"manage\": true\n" +
            "        }\n" +
            "    }\n" +
            "]";

    private static final String TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3Y1N6TDZ0a3RCNFhHcUtjbEZncnVaaHQtX3d5MkZUV0FlWUtaYWNSOTNnIn0.eyJqdGkiOiJmMzZlNWUwZS04Zjk1LTQzNmMtODNiOC1jOTRmNDcyZWRlNTQiLCJleHAiOjE1NTcyNjY1NjksIm5iZiI6MCwiaWF0IjoxNTU3MjMwNTY5LCJpc3MiOiJodHRwczovL2tleWNsb2FrLXNlcnZlci10ZXN0LmVhbmFkZXYub3JnL2F1dGgvcmVhbG1zL2V1cm9wZWFuYSIsImF1ZCI6InJlYWxtLW1hbmFnZW1lbnQiLCJzdWIiOiJkZTg5MGI1OS03NTFjLTRmNjMtYWUxYS1mODc5ODlkNDU1ZDUiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcGkta2V5LXNlcnZpY2UiLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiIzMGI2ZDkxNy0wMWIzLTRmMTItYmYyMi1lZjkxOWQ0ZjdiZDQiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIkFQSSJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFwaS1rZXktc2VydmljZSI6eyJyb2xlcyI6WyJ1bWFfcHJvdGVjdGlvbiJdfSwicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXJlYWxtIiwidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsInJlYWxtLWFkbWluIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInF1ZXJ5LXJlYWxtcyIsInZpZXctYXV0aG9yaXphdGlvbiIsInF1ZXJ5LWNsaWVudHMiLCJxdWVyeS11c2VycyIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJ2aWV3LWV2ZW50cyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtYXV0aG9yaXphdGlvbiIsIm1hbmFnZS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIl19fSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSIsImNsaWVudElkIjoiYXBpLWtleS1zZXJ2aWNlIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJjbGllbnRIb3N0IjoiMTUwLjI1NC4xNjkuMTAwIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LWFwaS1rZXktc2VydmljZSIsImNsaWVudEFkZHJlc3MiOiIxNTAuMjU0LjE2OS4xMDAiLCJlbWFpbCI6InNlcnZpY2UtYWNjb3VudC1hcGkta2V5LXNlcnZpY2VAcGxhY2Vob2xkZXIub3JnIn0.UoENMoInw81KRWkRW7divlPpGjKTgluZaU2cyZOqw7TU92cg7b2ELFBtv-Myc1rmap2Ha-VaKRc5cVsR_wwIiqYPELkwSTqC8yMNjEJdfg0MQyDnCtxP_72ehgP9YRhMrR1JB1TeXMChhwn1BDpdRQYdZjxRQCSArGy_lQHlDjU5hLJbdV3ZWjq8-l-uIWuJiviMHG2I3J34ioyKEEi6Xo7OhclXjcQ-OmPYRBTnGZBu908IFH9b23NxOOssPZxzYr3n6Qf9HPoaJ_VEja1OOeHDCCJcBtw4ww8TnkcRaA1llugBSS5iO9Fku_CZqEEeMkG3OdUpyn7Cuzahuac5KA";
    private static final String REALM_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp7sc54z9WkhvzCLTumC/lUq25iebcJbtk11qQY6CgAsWzXQ5fQHTQTe5bmc7moZTsDDgNWD6PHiQAUce2tMLNA1l9QFJQQXeWl7OOeFHw40erLQMbCFP9GKizMqFHSbwjgaFfyJGud6Z9KpRZ8vwyPQsxu8wB4Vi8tM3JSCRDCn3NhcRkw1KIBWboiPu4W02+XPkK7tqsotY8Dwd//Iudq5wU865Tx+9DNR0Kr/SyJaCIvwIN5agsu7dOVPQChoWkxUnOvJxpiI20jahLng5E/rxUYJD+a9Ih1CNCsQTLjAcjMxBKW0m97BmPy0rhlf1gWlhM+6/J0y8siq7WmwV9wIDAQAB";
    private static final String APP_NAME                     = "App name";
    private static final String WEBSITE                      = "www.website.com";
    private static final String SECTOR                       = "Sector";
    private static final String COMPANY                      = "Company";
    private static final String CLIENT_ID                    = "client";
    private static final String CLIENT_SECRET                = "secret";
    private static final String NEW_CLIENT_SECRET            = "134d4ec9-a26e-4dcb-93b7-13e22606eb9d";
    private static final String ACCESS_TOKEN_STRING          = "token1";
    private static final String EMPTY_CLIENT_REPRESENTATIONS = "[]";
    private static final String FIRST_NAME                   = "Name";
    private static final String LAST_NAME                    = "Surname";
    private static final String EMAIL                        = "name.surname@mail.com";

    @Mock
    private AccessToken accessToken;

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private KeycloakTokenVerifier keycloakTokenVerifier;

    private KeycloakProperties kcProperties = new KeycloakProperties("https://keycloak-server-test.eanadev.org/auth",
                                                                     "europeana",
                                                                     true,
                                                                     REALM_PUBLIC_KEY);

    @InjectMocks
    private KeycloakManager keycloakManager = new KeycloakManager(kcProperties);


    @PrepareForTest({KeycloakBuilder.class, KeycloakTokenVerifier.class})
    @Test
    public void authenticateClient() throws VerificationException {
        prepareForAuthentication();

        KeycloakPrincipal<KeycloakSecurityContext> principal = keycloakManager.authenticateClient(CLIENT_ID, CLIENT_SECRET);
        Assert.assertNotNull(principal);
        Assert.assertNotNull(principal.getKeycloakSecurityContext());
        Assert.assertEquals(accessToken, principal.getKeycloakSecurityContext().getAccessToken());
        Assert.assertEquals(ACCESS_TOKEN_STRING, principal.getKeycloakSecurityContext().getAccessTokenString());
    }

    private void prepareForAuthentication() throws VerificationException {
        KeycloakBuilder keycloakBuilder = Mockito.mock(KeycloakBuilder.class);
        PowerMockito.mockStatic(KeycloakBuilder.class);
        PowerMockito.when(KeycloakBuilder.builder()).thenReturn(keycloakBuilder);
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
        Mockito.when(tokenResponse.getToken()).thenReturn(ACCESS_TOKEN_STRING);
        Mockito.when(keycloakTokenVerifier.verifyToken(Mockito.anyString())).thenReturn(accessToken);
    }

    @Test(timeout = 2000)
    public void createClient() throws ApiKeyException, IOException {
        ApiKeyRequest           apiKeyCreate    = prepareApiKeyCreate();
        KeycloakSecurityContext securityContext = prepareForCreateClient();

        ApiKeySecret apiKey = keycloakManager.createClient(securityContext, apiKeyCreate);
        Assert.assertNotNull(apiKey);
        Assert.assertEquals(apiKeyCreate.getFirstName(), apiKey.getFirstName());
        Assert.assertEquals(apiKeyCreate.getLastName(), apiKey.getLastName());
        Assert.assertEquals(apiKeyCreate.getEmail(), apiKey.getEmail());
        Assert.assertEquals(NEW_CLIENT_SECRET, apiKey.getClientSecret());
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
               .thenReturn(new ByteArrayInputStream(EMPTY_CLIENT_REPRESENTATIONS.getBytes(StandardCharsets.UTF_8)));

        CloseableHttpResponse secondGetResponse   = Mockito.mock(CloseableHttpResponse.class);
        StatusLine            secondGetStatusLine = Mockito.mock(StatusLine.class);
        Mockito.when(secondGetResponse.getStatusLine()).thenReturn(secondGetStatusLine);
        Mockito.when(secondGetStatusLine.getStatusCode()).thenReturn(200);
        HttpEntity secondGetEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(secondGetResponse.getEntity()).thenReturn(secondGetEntity);
        Mockito.when(secondGetEntity.getContent())
               .thenReturn(new ByteArrayInputStream(CLIENT_REPRESENTATIONS.getBytes(StandardCharsets.UTF_8)));

        CloseableHttpResponse secretGetResponse   = Mockito.mock(CloseableHttpResponse.class);
        StatusLine            secretGetStatusLine = Mockito.mock(StatusLine.class);
        Mockito.when(secretGetResponse.getStatusLine()).thenReturn(secretGetStatusLine);
        Mockito.when(secretGetStatusLine.getStatusCode()).thenReturn(200);
        HttpEntity secretGetEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(secretGetResponse.getEntity()).thenReturn(secretGetEntity);
        Mockito.when(secretGetEntity.getContent())
               .thenReturn(new ByteArrayInputStream(CREDENTIAL_REPRESENTATION.getBytes(StandardCharsets.UTF_8)));

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
        return new ApiKeyRequest(FIRST_NAME, LAST_NAME, EMAIL, APP_NAME, COMPANY);
    }

//    @Test
    public void getAuthoritiesForRealm() throws VerificationException {
        AccessToken                  accessToken         = prepareVerifier();
        List<String>                 roles               = prepareRoles(false);
        Collection<GrantedAuthority> authorityCollection = keycloakManager.getAuthorities(accessToken);

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
        Collection<GrantedAuthority> authorityCollection = keycloakManager.getAuthorities(accessToken);

        Assert.assertNotNull(authorityCollection);
        Assert.assertFalse(authorityCollection.isEmpty());
        authorityCollection.forEach(grantedAuthority -> {
            Assert.assertTrue(roles.contains(grantedAuthority.getAuthority()));
        });
    }

    private List<String> prepareRoles(boolean useResourceRoleMappings) {
        List<String> roles = new ArrayList<>();
        if (useResourceRoleMappings) {
            ReflectionTestUtils.setField(keycloakManager, "useResourceRoleMappings", true);
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

    private AccessToken prepareVerifier() throws VerificationException {
//        KeycloakTokenVerifier verifier = new KeycloakTokenVerifier(null);
        KeycloakTokenVerifier verifier = new KeycloakTokenVerifier(REALM_PUBLIC_KEY);
//        ReflectionTestUtils.setField(verifier, "realmPublicKey", REALM_PUBLIC_KEY);
//        ReflectionTestUtils.invokeMethod(verifier, "init");
        return keycloakTokenVerifier.verifyToken(TOKEN);
    }

//    @Test
    public void isOwnerWhenOwner() {
        KeycloakAuthenticationToken keycloakAuthenticationToken = Mockito.mock(KeycloakAuthenticationToken.class);
        KeycloakSecurityContext     securityContext             = Mockito.mock(KeycloakSecurityContext.class);
        Mockito.when(keycloakAuthenticationToken.getName()).thenReturn(CLIENT_ID);
        Mockito.when(keycloakAuthenticationToken.getCredentials()).thenReturn(securityContext);

        boolean authorized = keycloakManager.isOwner(CLIENT_ID, keycloakAuthenticationToken);

        Assert.assertTrue(authorized);
    }

//    @Test
    public void isOwnerWhenOther() {
        KeycloakAuthenticationToken keycloakAuthenticationToken = Mockito.mock(KeycloakAuthenticationToken.class);
        KeycloakSecurityContext     securityContext             = Mockito.mock(KeycloakSecurityContext.class);
        Mockito.when(keycloakAuthenticationToken.getName()).thenReturn(CLIENT_ID);
        Mockito.when(keycloakAuthenticationToken.getCredentials()).thenReturn(securityContext);

        boolean authorized = keycloakManager.isOwner("other key", keycloakAuthenticationToken);

        Assert.assertFalse(authorized);
    }

//    @Test
    public void isClientAuthorizedWhenManager() throws VerificationException {
        KeycloakAuthenticationToken keycloakAuthenticationToken = Mockito.mock(KeycloakAuthenticationToken.class);
        KeycloakSecurityContext     securityContext             = Mockito.mock(KeycloakSecurityContext.class);
        AccessToken                 accessToken                 = prepareVerifier();
        prepareRoles(true);
        Collection<GrantedAuthority> authorityCollection = keycloakManager.getAuthorities(accessToken);
        Mockito.when(keycloakAuthenticationToken.getAuthorities()).thenReturn(authorityCollection);
        Mockito.when(keycloakAuthenticationToken.getName()).thenReturn("manager");
        Mockito.when(keycloakAuthenticationToken.getCredentials()).thenReturn(securityContext);

        boolean authorized = keycloakManager.isManagerClientAuthorized(keycloakAuthenticationToken);

        Assert.assertTrue(authorized);
    }

//    @Test
    public void isClientAuthorizedWhenOther() {
        KeycloakAuthenticationToken keycloakAuthenticationToken = Mockito.mock(KeycloakAuthenticationToken.class);
        KeycloakSecurityContext     securityContext             = Mockito.mock(KeycloakSecurityContext.class);
        Mockito.when(keycloakAuthenticationToken.getName()).thenReturn(CLIENT_ID);
        Mockito.when(keycloakAuthenticationToken.getCredentials()).thenReturn(securityContext);

        boolean authorized = keycloakManager.isManagerClientAuthorized(keycloakAuthenticationToken);

        Assert.assertFalse(authorized);
    }

    @Test(expected = ApiKeyException.class)
    public void updateClientWhenClientMissing() throws IOException, ApiKeyException {
        ApiKeyRequest           apiKeyDetails   = prepareApiKeyUpdate();
        KeycloakSecurityContext securityContext = prepareForUpdateClient(false, true);

        keycloakManager.updateClient(securityContext, apiKeyDetails, CLIENT_ID);
    }

    @Test
    public void updateClientWhenClientExists() throws IOException, ApiKeyException {
        ApiKeyRequest           apiKeyUpdate    = prepareApiKeyUpdate();
        KeycloakSecurityContext securityContext = prepareForUpdateClient(true, true);

        keycloakManager.updateClient(securityContext, apiKeyUpdate, CLIENT_ID);
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
                       .thenReturn(new ByteArrayInputStream(CLIENT_REPRESENTATIONS.getBytes(StandardCharsets.UTF_8)));
            } else {
                Mockito.when(getEntity.getContent())
                       .thenReturn(new ByteArrayInputStream(DISABLED_CLIENT_REPRESENTATIONS.getBytes(StandardCharsets.UTF_8)));
            }
        } else {
            Mockito.when(getEntity.getContent())
                   .thenReturn(new ByteArrayInputStream(EMPTY_CLIENT_REPRESENTATIONS.getBytes(StandardCharsets.UTF_8)));
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
        return new ApiKeyRequest(FIRST_NAME, LAST_NAME, EMAIL, APP_NAME, COMPANY, SECTOR, WEBSITE);
    }

    @Test(expected = ApiKeyException.class)
    public void invalidateClientWhenClientMissing() throws IOException, ApiKeyException {
        KeycloakSecurityContext securityContext = prepareForUpdateClient(false, true);
        keycloakManager.disableClient(CLIENT_ID, securityContext);
    }

    @Test
    public void invalidateClientWhenClientExists() throws IOException, ApiKeyException {
        KeycloakSecurityContext securityContext = prepareForUpdateClient(true, true);
        keycloakManager.disableClient(CLIENT_ID, securityContext);
    }

    @Test(expected = ApiKeyException.class)
    public void reenableClientWhenClientMissing() throws IOException, ApiKeyException {
        KeycloakSecurityContext securityContext = prepareForUpdateClient(false, true);
        keycloakManager.enableClient(CLIENT_ID, securityContext);
    }

    @Test
    public void reenableClientWhenClientExists() throws IOException, ApiKeyException {
        KeycloakSecurityContext securityContext = prepareForUpdateClient(true, false);
        keycloakManager.enableClient(CLIENT_ID, securityContext);
    }

}