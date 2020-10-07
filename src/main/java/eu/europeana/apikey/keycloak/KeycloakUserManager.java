package eu.europeana.apikey.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import eu.europeana.apikey.config.KeycloakProperties;
import eu.europeana.apikey.domain.ApiKeyRequest;
import eu.europeana.apikey.domain.ApiKeySecret;
import eu.europeana.apikey.exception.ApiKeyException;
import eu.europeana.apikey.exception.KCClientExistsException;
import eu.europeana.apikey.exception.MissingKCClientException;
import eu.europeana.apikey.util.PassGenerator;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.*;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.springsecurity.KeycloakAuthenticationException;
import org.keycloak.adapters.springsecurity.account.KeycloakRole;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Class for working with Keycloak and it's
 * <a href="https://www.keycloak.org/docs-api/6.0/rest-api/index.html">Rest Admin API</a>.<br/>
 * <p>
 * Note that there are 2 client id's used by keycloak:
 * <ol>
 *     <li>ClientId which is the same as an apikey (string)</li>
 *     <li>id which is an internal id (hash) of the client. This is called "id of client (not clientId)" in the keycloak
 *  *  documentation and saved as keycloakId in an apikey object.</li>
 * </ol>
 *  In other words:
 *  <code>
 *    apiKey.getId().equals(keycloakClient.getClientId());
 *    apiKey.getKeycloakId.equals(keycloakClient.getId());
 *  </code>
 */
@Service
public class KeycloakUserManager {
    private static final Logger LOG = LogManager.getLogger(KeycloakUserManager.class);

    private static final String MASTER_REALM = "master";
    private static final String USER_ENDPOINT = "%s/admin/realms/%s/users/%s";
    private static final String ERROR_COMMUNICATING_WITH_KEYCLOAK = "Error communicating with Keycloak";
    private static final String RECEIVED = ": received ";

    private final        ObjectMapper          mapper                            = new ObjectMapper();
    private final        KeycloakTokenVerifier keycloakTokenVerifier;
    private final        KeycloakTokenVerifier keycloakMasterTokenVerifier;
    private final        KeycloakProperties    kcProperties;

    /**
     * Http client used for communicating with Keycloak where Keycloak admin client is not appropriate
     */
    private              CloseableHttpClient   httpClient;

    public KeycloakUserManager(KeycloakProperties kcProperties) {
        this.kcProperties = kcProperties;
        this.keycloakTokenVerifier = new KeycloakTokenVerifier(kcProperties.getRealmPublicKey());
        this.keycloakMasterTokenVerifier = new KeycloakTokenVerifier(kcProperties.getMasterPublicKey());
    }

    @PostConstruct
    public void init() {
        httpClient = HttpClients.createDefault();
    }

    @PreDestroy
    public void clean() {
        try {
            httpClient.close();
        } catch (IOException e) {
            LOG.error("Closing http client failed", e);
        }
    }

    KeycloakPrincipal<KeycloakSecurityContext> authenticateAdminUser(String username,
                                                                     String password,
                                                                     String clientId,
                                                                     String grantType) {
        Keycloak keycloak = KeycloakBuilder.builder()
                                           .realm(MASTER_REALM)
                                           .serverUrl(kcProperties.getAuthServerUrl())
                                           .username(username)
                                           .password(password)
                                           .clientId(clientId)
                                           .grantType(grantType)
                                           .build();
        AccessTokenResponse accessTokenResponse;
        try {
            LOG.debug("Retrieving access token for user {}...", username);
            accessTokenResponse = keycloak.tokenManager().getAccessToken();
            if (accessTokenResponse == null) {
                LOG.error("No access token retrieved for user {}!", username);
                return null;
            }
        } catch (RuntimeException eek) {
            throw new AuthenticationServiceException("Retrieving access token failed for user " + username, eek);
        }

        try {
            LOG.debug("Verifying access token for user {}...", username);
            AccessToken accessToken = keycloakMasterTokenVerifier.verifyToken(accessTokenResponse.getToken());
            if (accessToken != null) {
                return new KeycloakPrincipal<>(username,
                                               new KeycloakSecurityContext(keycloak,
                                                                           accessToken,
                                                                           accessTokenResponse.getToken(),
                                                                           keycloakTokenVerifier));
            }
        } catch (VerificationException e) {
            throw new KeycloakAuthenticationException("Verification failed for user " + username, e);
        }
        LOG.error("Verifying access token failed for user {}!", username);
        return null;
    }

    /**
     * Check whether the user with a given userId exists in Keycloak
     *
     * @param userId               identifying the user
     * @param adminSecurityContext admin level auth token (context) to authorize the request
     * @return true when user with id userId exists
     * @throws ApiKeyException if this goes not as intended
     */
    public UserRepresentation userDetails(String userId, KeycloakSecurityContext adminSecurityContext) throws ApiKeyException {
        HttpGet httpGet = prepareGetUserRequest(userId, adminSecurityContext.getAccessTokenString());
        LOG.debug("Checking if user with ID {} exists...", userId);
        UserRepresentation user   = getUser(httpGet);
        if (null != user){
            LOG.debug("Keycloak user with userID {} exists!", userId);
            return user;
        } else {
            LOG.warn("Keycloak user with userID {} cannot be found!", userId);
            return null;
        }
    }

    /**
     * Deletes a client from Keycloak
     *
     * @param adminSecurityContext security context with access token
     * @param userId          the id of the client that is to be deleted
     */
    public void deleteUser(String userId, KeycloakSecurityContext adminSecurityContext) throws ApiKeyException {
        HttpDelete httpDelete = new HttpDelete(KeycloakUriBuilder.fromUri(String.format(USER_ENDPOINT,
                                                                                        kcProperties.getAuthServerUrl(),
                                                                                        kcProperties.getRealm(),
                                                                                        userId)).build());
        addAuthorizationHeader(adminSecurityContext.getAccessTokenString(), httpDelete);
        try (CloseableHttpResponse response = httpClient.execute(httpDelete)) {
            LOG.debug("Received response for user {} from Keycloak: {}", httpDelete, response);
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_NO_CONTENT) {
                throw new ApiKeyException(
                        ERROR_COMMUNICATING_WITH_KEYCLOAK + RECEIVED + response.getStatusLine().getStatusCode() +
                        " - " + response.getStatusLine().getReasonPhrase());
            }
        } catch (IOException | ApiKeyException e) {
            throw new ApiKeyException(ERROR_COMMUNICATING_WITH_KEYCLOAK, e);
        }
    }

    /**
     * Configure get request for retrieving the User identified by userId from Keycloak
     *
     * @param userId     api key used as keycloak userId
     * @param adminToken access token to authorize request
     * @return configured HttpGet request
     */
    private HttpGet prepareGetUserRequest(String userId, String adminToken) {
        HttpGet httpGet = new HttpGet(KeycloakUriBuilder.fromUri(String.format(USER_ENDPOINT,
                                                                               kcProperties.getAuthServerUrl(),
                                                                               kcProperties.getRealm(),
                                                                               userId)).build());
        addAuthorizationHeader(adminToken, httpGet);
        return httpGet;
    }

    /**
     * Retrieve details about a given user identified by userId
     *
     * @param httpGet get request
     * @return a list of retrieved users
     * @throws ApiKeyException in case keycloak refuses to communicate
     */
    private UserRepresentation getUser(HttpGet httpGet) throws ApiKeyException {
        LOG.debug("Sending user representation request to Keycloak...");
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            LOG.debug("Received user representation from Keycloak");
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                InputStream is = response.getEntity().getContent();
                return mapper.readValue(is, UserRepresentation.class);
            }
            throw new ApiKeyException(
                    ERROR_COMMUNICATING_WITH_KEYCLOAK + RECEIVED + response.getStatusLine().getStatusCode() + " - " +
                    response.getStatusLine().getReasonPhrase());
        } catch (IOException e) {
            throw new ApiKeyException(ERROR_COMMUNICATING_WITH_KEYCLOAK, e);
        }
    }

    /**
     * Retrieve the UserId ("sub" (Subject) in JWT terms) from the user token
     *
     * @param userTokenString base64 encoded JWT token
     * @return UserId / value of "sub"
     */
    public String extractUserId(String userTokenString) {
        try {
            return keycloakTokenVerifier.retrieveUserToken(userTokenString).getSubject();
        } catch (VerificationException e) {
            throw new KeycloakAuthenticationException("Error parsing usertoken", e);
        }
    }

    /**
     * Add authorization header with the given access token
     *
     * @param accessToken access token to put in the header
     * @param request     request to which the header will be added
     */
    private void addAuthorizationHeader(String accessToken, HttpRequestBase request) {
        request.addHeader("Authorization", "bearer " + accessToken);
    }
}
