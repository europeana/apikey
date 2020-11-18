package eu.europeana.apikey.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import eu.europeana.apikey.config.KeycloakProperties;
import eu.europeana.apikey.domain.ApiKey;
import eu.europeana.apikey.domain.ApiKeyRequest;
import eu.europeana.apikey.exception.ApiKeyException;
import eu.europeana.apikey.exception.KCClientExistsException;
import eu.europeana.apikey.exception.MissingKCClientException;
import eu.europeana.apikey.util.PassGenerator;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
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
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.http.*;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import static eu.europeana.apikey.config.ApikeyDefinitions.*;

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
public class KeycloakClientManager {
    private static final Logger                LOG    = LogManager.getLogger(KeycloakClientManager.class);
    private final        ObjectMapper          mapper = new ObjectMapper();
    private final        KeycloakTokenVerifier keycloakTokenVerifier;
    private final        KeycloakProperties    kcProperties;
    private              CloseableHttpClient   httpClient;

    public KeycloakClientManager(KeycloakProperties kcProperties) {
        this.kcProperties = kcProperties;
        this.keycloakTokenVerifier = new KeycloakTokenVerifier(kcProperties.getRealmPublicKey());
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

    /**
     * Authenticate the client that executed the request. Authentication is done following the client credentials grant type.
     * Access token and refresh token are stored in the returned KeycloakSecurityContext together with the configured admin
     * client that can be used to refresh tokens.
     *
     * @param clientId     client-id of the client executing the request
     * @param clientSecret client secret used to authenticate the client in Keycloak
     * @return security context with configured admin client together with access and refresh tokens
     */
    KeycloakPrincipal<KeycloakSecurityContext> authenticateClient(String clientId, String clientSecret) {
        Keycloak keycloak = KeycloakBuilder.builder()
                                           .realm(kcProperties.getRealm())
                                           .serverUrl(kcProperties.getAuthServerUrl())
                                           .clientId(clientId)
                                           .clientSecret(clientSecret)
                                           .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                                           .build();
        AccessTokenResponse accessTokenResponsen;
        try {
            LOG.debug("Retrieving access token for client {}...", clientId);
            accessTokenResponsen = keycloak.tokenManager().getAccessToken();
            if (accessTokenResponsen == null) {
                LOG.error("No access token retrieved for client {}!", clientId);
                return null;
            }
        } catch (RuntimeException anyException) {
            throw new AuthenticationServiceException("Retrieving access token failed for client " + clientId,
                                                     anyException);
        }

        try {
            LOG.debug("Verifying access token for client {}...", clientId);
            AccessToken accessToken = keycloakTokenVerifier.verifyToken(accessTokenResponsen.getToken());
            if (accessToken != null) {
                return new KeycloakPrincipal<>(clientId,
                                               new KeycloakSecurityContext(keycloak,
                                                                           accessToken,
                                                                           accessTokenResponsen.getToken(),
                                                                           keycloakTokenVerifier));
            }
        } catch (VerificationException e) {
            throw new KeycloakAuthenticationException("Authentication failed for client " + clientId, e);
        }
        LOG.error("Verifying access token failed for client {}!", clientId);
        return null;
    }

    /**
     * Creates a new Keycloak client linked to the provided Apikey. This method is used:
     *
     * - when creating a combined Apikey and Client;
     * - and when adding a Client to an existing Apikey.
     * The required data are supplied by the ApiKey object.
     *
     * When a client is successfully created in Keycloak, the Client secret (aka Secret Key) is retrieved from Keycloak
     * with the getClientSecret() method and passed back to the Controller, so that it can be sent to the user.
     * The Client ID is stored as KeycloakID in the database record of the linked Apikey.
     *
     * @param securityContext security context with access token
     * @param key             Apikey to link the Client to be created to, and to copy some data from that are added
     *                        to the Keycloak Client
     * @return ClientRepresentation representing the newly created client in Keycloak, including Secret (Key)
     */
    public ClientRepresentation createClient(KeycloakSecurityContext securityContext, ApiKey key) throws
                                                                                                  ApiKeyException {
        // Check if there already is a client with this apikey
        if (clientExists(key.getApiKey(), securityContext.getAccessTokenString())) {
            throw new KCClientExistsException(key.getApiKey());
        }
        // create keycloak client object to save
        ClientRepresentation newClientRep = new ClientRepresentation();
        newClientRep.setClientId(key.getApiKey());
        newClientRep.setPublicClient(false);
        newClientRep.setProtocol("openid-connect");
        newClientRep.setName(String.format(CLIENT_NAME,
                                           key.getAppName(),
                                           (StringUtils.isBlank(key.getCompany()) ? "" : key.getCompany())));
        newClientRep.setDescription(String.format(CLIENT_DESCRIPTION,
                                                  key.getFirstName(),
                                                  key.getLastName(),
                                                  key.getEmail()));
        newClientRep.setDirectAccessGrantsEnabled(false);
        newClientRep.setServiceAccountsEnabled(true);
        ArrayList<String> redirectUris = new ArrayList<>();
        redirectUris.add("*");
        newClientRep.setRedirectUris(redirectUris);

        // create post request and send it
        HttpPost httpPost = new HttpPost(KeycloakUriBuilder.fromUri(String.format(CLIENTS_ENDPOINT,
                                                                                  kcProperties.getAuthServerUrl(),
                                                                                  kcProperties.getRealm())).build());
        addAuthorizationHeader(securityContext.getAccessTokenString(), httpPost);
        addRequestEntity(newClientRep, httpPost);
        sendClientRequestToKeycloak(httpPost, HttpStatus.CREATED.value(), newClientRep);
        LOG.debug("Client with ID {} and client_id {} was created", newClientRep.getId(), newClientRep.getClientId());

        return getClientSecret(key.getApiKey(), securityContext);
    }

    /**
     * Updates the client representation with the new values supplied with the update request.
     *
     * @param securityContext   security context with access token
     * @param apiKeyUpdate      registration data to be updated
     * @param apiKey            passed separately because the ApiKeyRequest does not contain it
     * @return changed client representation
     */
    public void updateClient(KeycloakSecurityContext securityContext, ApiKeyRequest apiKeyUpdate, String apiKey) throws
                                                                                                                 ApiKeyException {
        ClientRepresentation clientRepresentation = getClientRepresentation(apiKey, securityContext);
        updateClient(updateClientRepresentation(clientRepresentation, apiKeyUpdate), securityContext);
    }


    private ClientRepresentation updateClientRepresentation(ClientRepresentation clientRepresentation,
                                                            ApiKeyRequest apiKeyUpdate) {
        if (apiKeyUpdate == null) {
            return clientRepresentation;
        }
        String appNameClientId = (StringUtils.isNotBlank(apiKeyUpdate.getAppName()) ? apiKeyUpdate.getAppName() : clientRepresentation
                .getClientId());
        String companySector = (StringUtils.isNotBlank(apiKeyUpdate.getCompany()) ? apiKeyUpdate.getCompany() : "N/A") +
                               (StringUtils.isNotBlank(apiKeyUpdate.getSector()) ?
                                ", sector: " + apiKeyUpdate.getSector() : "");

        clientRepresentation.setName(String.format(CLIENT_NAME, appNameClientId, companySector));
        clientRepresentation.setDescription(String.format(CLIENT_DESCRIPTION,
                                                          apiKeyUpdate.getFirstName(),
                                                          apiKeyUpdate.getLastName(),
                                                          apiKeyUpdate.getEmail()));
        return clientRepresentation;
    }

    /**
     * Performs actual call to Keycloak sending the updated client data.
     * Only Name and Description are subject of an update, they both consist of concatedated data from the Apikey
     *
     * @param clientRepresentation  client representation that will be sent as request body
     * @param securityContext       security context with the access token
     * @throws ApiKeyException      if keycloak isn't home
     */
    private void updateClient(ClientRepresentation clientRepresentation, KeycloakSecurityContext securityContext) throws
                                                                                                                  ApiKeyException {
        HttpPut httpPut = new HttpPut(KeycloakUriBuilder.fromUri(String.format(CLIENTS_UPDATE_ENDPOINT,
                                                                               kcProperties.getAuthServerUrl(),
                                                                               kcProperties.getRealm(),
                                                                               clientRepresentation.getId())).build());
        addAuthorizationHeader(securityContext.getAccessTokenString(), httpPut);
        addRequestEntity(clientRepresentation, httpPut);
        sendClientRequestToKeycloak(httpPut, HttpStatus.NO_CONTENT.value(), clientRepresentation);
    }

    /**
     * Deletes a client from Keycloak
     *
     * @param securityContext security context with access token
     * @param apiKey          the id of the client that is to be deleted
     * @throws ApiKeyException when trouble strikes
     */
    public void deleteClient(KeycloakSecurityContext securityContext, String apiKey) throws ApiKeyException {
        ClientRepresentation clientRepresentation = getClientRepresentation(apiKey, securityContext);
        HttpDelete httpDelete = new HttpDelete(KeycloakUriBuilder.fromUri(String.format(CLIENTS_UPDATE_ENDPOINT,
                                                                                        kcProperties.getAuthServerUrl(),
                                                                                        kcProperties.getRealm(),
                                                                                        clientRepresentation.getId()))
                                                                 .build());
        addAuthorizationHeader(securityContext.getAccessTokenString(), httpDelete);
        sendClientRequestToKeycloak(httpDelete, HttpStatus.NO_CONTENT.value(), clientRepresentation);
    }

    /**
     * Enables the client in Keycloak, but only if it was disabled
     *
     * @param clientId        client identifier
     * @param securityContext security context with access token
     * @throws ApiKeyException when client not found in Keycloak or update failed
     */
    public void enableClient(String clientId, KeycloakSecurityContext securityContext) throws ApiKeyException {
        ClientRepresentation clientRepresentation = getClientRepresentation(clientId, securityContext);
        if (Boolean.FALSE.equals(clientRepresentation.isEnabled())) {
            clientRepresentation.setEnabled(true);
            updateClient(clientRepresentation, securityContext);
        } else {
            LOG.warn("API key {} of client {} is already enabled",
                     clientRepresentation.getClientId(),
                     clientRepresentation.getId());
        }
    }

    /**
     * Disables the client in Keycloak, but only if it is enabled
     *
     * @param clientId        client identifier
     * @param securityContext security context with access token
     * @throws ApiKeyException when client not found in Keycloak or update failed
     */
    public void disableClient(String clientId, KeycloakSecurityContext securityContext) throws ApiKeyException {
        ClientRepresentation clientRepresentation = getClientRepresentation(clientId, securityContext);
        if (Boolean.TRUE.equals(clientRepresentation.isEnabled())) {
            clientRepresentation.setEnabled(false);
            updateClient(clientRepresentation, securityContext);
        } else {
            LOG.warn("API key {} of client {} is already disabled",
                     clientRepresentation.getClientId(),
                     clientRepresentation.getId());
        }
    }

    /**
     * Retrieve a list of clients using a configured get request.
     *
     * @param httpGet get request
     * @return a list of retrieved clients
     * @throws ApiKeyException in case keycloak refuses to communicate
     */
    private List<ClientRepresentation> getClients(HttpGet httpGet) throws ApiKeyException {
        LOG.debug("Sending getClients to Keycloak...");
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            LOG.debug("Received getClients from Keycloak");
            if (response.getStatusLine().getStatusCode() == HttpStatus.OK.value()) {
                InputStream is = response.getEntity().getContent();
                CollectionType mapCollectionType = mapper.getTypeFactory()
                                                         .constructCollectionType(List.class,
                                                                                  ClientRepresentation.class);
                return mapper.readValue(is, mapCollectionType);
            }
            throw new ApiKeyException(
                    ERROR_COMMUNICATING_WITH_KEYCLOAK + RECEIVED + response.getStatusLine().getStatusCode() + " - " +
                    response.getStatusLine().getReasonPhrase());
        } catch (IOException e) {
            throw new ApiKeyException(ERROR_COMMUNICATING_WITH_KEYCLOAK, e);
        }
    }

    /**
     * Retrieve client secret from Keycloak. In order to do it client id / UUID (client.id, not client.client_id)
     * must be retrieved first. This identifier is needed when requesting the client secret.
     * <p>
     * Note that we need to retrieve the newly created client from keycloak (reusing the one we sent to Keycloak to
     * create the account doesn't work)
     *
     * @param clientId        client id
     * @param securityContext security context with access token
     * @return client secret wrapped in ClientRepresentation object
     * @throws ApiKeyException when any exception happens during communication with Keycloak
     */
    private ClientRepresentation getClientSecret(String clientId, KeycloakSecurityContext securityContext) throws
                                                                                                           ApiKeyException {
        ClientRepresentation representation = getClientRepresentation(clientId, securityContext);
        HttpGet httpGet = new HttpGet(KeycloakUriBuilder.fromUri(String.format(CLIENT_SECRET_ENDPOINT,
                                                                               kcProperties.getAuthServerUrl(),
                                                                               kcProperties.getRealm(),
                                                                               representation.getId())).build());
        addAuthorizationHeader(securityContext.getAccessTokenString(), httpGet);

        String secret;
        LOG.debug("Sending getClientSecret of {} to Keycloak...", clientId);
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            LOG.debug("Received getClientSecret for {} from Keycloak", clientId);
            if (response.getStatusLine().getStatusCode() != HttpStatus.OK.value()) {
                throw new ApiKeyException(
                        ERROR_COMMUNICATING_WITH_KEYCLOAK + RECEIVED + response.getStatusLine().getStatusCode() +
                        " - " + response.getStatusLine().getReasonPhrase());
            }
            try (InputStream is = response.getEntity().getContent()) {
                secret = mapper.readValue(is, CredentialRepresentation.class).getValue();
            }
        } catch (IOException e) {
            throw new ApiKeyException(ERROR_COMMUNICATING_WITH_KEYCLOAK, e);
        }

        representation.setSecret(secret);
        return representation;
    }

    /**
     * Retrieve client secret from Keycloak. In order to do it client identifier (not client-id) must be retrieved first.
     * This identifier is needed when requesting the client secret.
     *
     * @param clientId        client id
     * @param securityContext security context with access token
     * @return client secret
     * @throws ApiKeyException when any exception happens during communication with Keycloak
     */
    private ClientRepresentation getClientRepresentation(String clientId,
                                                         KeycloakSecurityContext securityContext) throws
                                                                                                  ApiKeyException {
        HttpGet httpGet = prepareGetClientRequest(clientId, securityContext.getAccessTokenString());
        LOG.debug("Retrieving client representation for {}...", clientId);
        List<ClientRepresentation> clients = getClients(httpGet);
        if (clients == null || clients.isEmpty()) {
            throw new MissingKCClientException(clientId);
        }
        return clients.get(0);
    }

    private void sendClientRequestToKeycloak(HttpUriRequest httpRequest,
                                             int expectedHttpStatus,
                                             ClientRepresentation clientRep) throws ApiKeyException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending {} request for API key {} (client {}) to Keycloak...",
                      httpRequest.getMethod() + " " + httpRequest.getURI().getPath(),
                      clientRep.getClientId(),
                      clientRep.getId());
        }
        try (CloseableHttpResponse response = httpClient.execute(httpRequest)) {
            LOG.debug("Received response for client {} from Keycloak: {}", clientRep.getId(), response);
            if (response.getStatusLine().getStatusCode() != expectedHttpStatus) {
                throw new ApiKeyException(
                        ERROR_COMMUNICATING_WITH_KEYCLOAK + RECEIVED + response.getStatusLine().getStatusCode() +
                        " - " + response.getStatusLine().getReasonPhrase());
            }
        } catch (IOException e) {
            throw new ApiKeyException(ERROR_COMMUNICATING_WITH_KEYCLOAK, e);
        }
    }

    /**
     * Adds body to the request. The body is ClientRepresentation in json.
     *
     * @param clientRepresentation representation of the clinet to be sent to Keycloak
     * @param httpRequest          request to which the body will be attached
     * @throws ApiKeyException if problems arise while the client is created
     */
    private void addRequestEntity(ClientRepresentation clientRepresentation,
                                  HttpEntityEnclosingRequestBase httpRequest) throws ApiKeyException {
        httpRequest.addHeader("Content-Type", "application/json");
        HttpEntity entity;
        try {
            entity = new StringEntity(mapper.writeValueAsString(clientRepresentation), "UTF-8");
        } catch (JsonProcessingException e) {
            throw new ApiKeyException("Problem with creating client representation for the request", e);
        }
        httpRequest.setEntity(entity);
    }

    /**
     * Get resource authorities from the access token
     *
     * @param token access token object
     * @return collection of granted authorities to authorize resource access
     */
    Collection<GrantedAuthority> getAuthorities(AccessToken token) {
        List<GrantedAuthority> result = new ArrayList<>();
        if (kcProperties.isUseResourceRoleMappings()) {
            token.getResourceAccess().forEach((s, access) -> {
                if (access != null) {
                    access.getRoles().forEach(role -> result.add(new KeycloakRole(role)));
                }
            });
        } else {
            AccessToken.Access access = token.getRealmAccess();
            if (access != null) {
                access.getRoles().forEach(s -> result.add(new KeycloakRole(s)));
            }
        }
        return result;
    }

    public String checkifClientExists(String apiKey, KeycloakSecurityContext kcSecurityContext) throws ApiKeyException {
        HttpGet httpGet = prepareGetClientRequest(apiKey, kcSecurityContext.getAccessTokenString());
        LOG.debug("Checking if client with clientId {} exists...", apiKey);
        List<ClientRepresentation> clients = getClients(httpGet);
        if (clients != null && !clients.isEmpty()) {
            return clients.get(0).getId();
        } else {
            return null;
        }
    }


    /**
     * Check whether the client with a given clientId (apiKey) exists in Keycloak
     *
     * @param apiKey      api key to use as client-id
     * @param accessToken access token to authorize the request
     * @return true when apiKey belongs to a valid client
     * @throws ApiKeyException if this goes not as intended
     */
    private boolean clientExists(String apiKey, String accessToken) throws ApiKeyException {
        HttpGet httpGet = prepareGetClientRequest(apiKey, accessToken);
        LOG.debug("Checking if client {} exists...", apiKey);
        List<ClientRepresentation> clients = getClients(httpGet);
        boolean                    result  = (clients != null && !clients.isEmpty());
        LOG.debug("Keycloak client with API key {} exists = {}", apiKey, result);
        return result;
    }

    /**
     * Configure get request for getting a specific client with client-id equal to new api key
     *
     * @param apiKey      api key used as keycloak clientId
     * @param accessToken access token to authorize request
     * @return configured get request
     */
    private HttpGet prepareGetClientRequest(String apiKey, String accessToken) {
        HttpGet httpGet = new HttpGet(KeycloakUriBuilder.fromUri(String.format(CLIENTS_ENDPOINT,
                                                                               kcProperties.getAuthServerUrl(),
                                                                               kcProperties.getRealm()))
                                                        .queryParam("clientId", apiKey)
                                                        .build());
        addAuthorizationHeader(accessToken, httpGet);
        return httpGet;
    }

    /**
     * Checks whether the client for which the token was issued is the owner of the apikey
     *
     * @param apiKey                      api key to check
     * @param keycloakAuthenticationToken token issued for the caller of the request
     * @return true when authorized, false otherwise
     */
    public boolean isOwner(String apiKey, KeycloakAuthenticationToken keycloakAuthenticationToken) {
        if (apiKey == null || keycloakAuthenticationToken == null ||
            keycloakAuthenticationToken.getCredentials() == null) {
            return false;
        }

        // apikey parameter is the one that we want to check against the name in the authentication token
        return apiKey.equals(keycloakAuthenticationToken.getName());
    }

    /**
     * Checks whether the token was issued for a manager client
     *
     * @param keycloakAuthenticationToken token issued for the caller of the request
     * @return true when authorized, false otherwise
     */
    public boolean isManagerClientAuthorized(KeycloakAuthenticationToken keycloakAuthenticationToken) {
        if (keycloakAuthenticationToken == null || keycloakAuthenticationToken.getCredentials() == null) {
            return false;
        }

        Collection<GrantedAuthority> authorities = keycloakAuthenticationToken.getAuthorities();
        if (authorities == null || authorities.isEmpty()) {
            return false;
        }

        Optional<String> manager = authorities.stream()
                                              .map(GrantedAuthority::getAuthority)
                                              .filter(MANAGE_CLIENTS_ROLE::equals)
                                              .findFirst();
        return manager.isPresent();
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
