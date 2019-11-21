package eu.europeana.apikey.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import eu.europeana.apikey.domain.ApiKeyRequest;
import eu.europeana.apikey.exception.ApiKeyException;
import eu.europeana.apikey.domain.FullApikey;
import eu.europeana.apikey.exception.MissingKCClientException;
import eu.europeana.apikey.util.PassGenerator;
import org.apache.commons.lang3.RandomUtils;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Class for working with Keycloak
 */
@Component
public class KeycloakManager {
    private static final Logger LOG = LogManager.getLogger(KeycloakManager.class);

    /**
     * Template for client name
     */
    private static final String CLIENT_NAME = "%s (%s)";

    /**
     * Template for client description
     */
    private static final String CLIENT_DESCRIPTION = "%s %s (%s)";

    /**
     * Template for clients endpoint
     */
    private static final String CLIENTS_ENDPOINT = "%s/admin/realms/%s/clients";

    /**
     * Template for client-secret endpoint
     */
    private static final String CLIENT_SECRET_ENDPOINT = "%s/admin/realms/%s/clients/%s/client-secret";

    /**
     * Template for clients update endpoint
     */
    private static final String CLIENTS_UPDATE_ENDPOINT = "%s/admin/realms/%s/clients/%s";

    /**
     * Role for managing clients used to authorize access by Manager Client
     */
    private static final String MANAGE_CLIENTS_ROLE = "manage-clients";

    private static final String ERROR_COMMUNICATING_WITH_KEYCLOAK = "Error communicating with Keycloak";

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.use-resource-role-mappings}")
    private boolean useResourceRoleMappings;

    /**
     * Http client used for communicating with Keycloak where Keycloak admin client is not appropriate
     */
    private CloseableHttpClient httpClient;

    /**
     * Object mapper used for serialization and deserialization Keycloak objects to / from json
     */
    private ObjectMapper mapper = new ObjectMapper();

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
                .realm(realm)
                .serverUrl(authServerUrl)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();

        AccessTokenResponse token;
        try {
            token = keycloak.tokenManager().getAccessToken();
            if (token == null) {
                return null;
            }
        } catch (RuntimeException anyException) {
            LOG.error("Retrieving access token failed", anyException);
            throw new AuthenticationServiceException("Retrieving access token failed");
        }

        try {
            AccessToken accessToken = KeycloakTokenVerifier.verifyToken(token.getToken());
            if (accessToken != null) {
                return new KeycloakPrincipal<>(clientId, new KeycloakSecurityContext(keycloak, accessToken, token.getToken()));
            }
        } catch (VerificationException e) {
            throw new KeycloakAuthenticationException("Authentication failed for client " + clientId, e);
        }
        return null;
    }

    /**
     * Create a new client in Keycloak. ApikeyDetails object is used to populate all the needed client registration data.
     * Keycloak security context will be used to authorize Keycloak requests with access token. When a client is successfully
     * created in Keycloak the generated secret is retrieved from Keycloak and stored in Apikey object that will be used to
     * store the entry in apikey database.
     *
     * @param securityContext security context with access token
     * @param apikeyCreate    object containing registration data from the original request
     * @return new Apikey object with all necessary fields.
     * @throws ApiKeyException when there is a failure
     */
    public FullApikey createClient(KeycloakSecurityContext securityContext, ApiKeyRequest apikeyCreate) throws ApiKeyException {
        // ClientId must be unique
        String newApiKey = generateClientId(securityContext);

        // create client in Keycloak
        ClientRepresentation clientRepresentation = createClientRepresentation(newApiKey, apikeyCreate);
        HttpPost httpPost = new HttpPost(KeycloakUriBuilder
                .fromUri(String.format(CLIENTS_ENDPOINT, authServerUrl, realm)).build());
        addAuthorizationHeader(securityContext.getAccessTokenString(), httpPost);
        addRequestEntity(clientRepresentation, httpPost);
        sendRequestToKeycloak(httpPost, HttpStatus.SC_CREATED, clientRepresentation);
        ClientRepresentation createdClient = getClientSecret(newApiKey, securityContext);

        // create DB entity
        FullApikey apikey = new FullApikey(newApiKey,
                apikeyCreate.getFirstName(),
                apikeyCreate.getLastName(),
                apikeyCreate.getEmail(),
                apikeyCreate.getAppName(),
                apikeyCreate.getCompany(),
                createdClient.getSecret());
        apikey.setKeycloakId(createdClient.getId());
        if (null != apikeyCreate.getWebsite()) {
            apikey.setWebsite(apikeyCreate.getWebsite());
        }
        if (null != apikeyCreate.getCompany()) {
            apikey.setCompany(apikeyCreate.getCompany());
        }
        if (null != apikeyCreate.getSector()) {
            apikey.setSector(apikeyCreate.getSector());
        }
        return apikey;
    }

    /**
     * Create a new client in Keycloak. ApikeyDetails object is used to populate all the needed client registration data.
     * Keycloak security context will be used to authorize Keycloak requests with access token. When a client is successfully
     * created in Keycloak the generated secret is retrieved from Keycloak and stored in Apikey object that will be used to
     * store the entry in apikey database.
     *
     * @param securityContext security context with access token
     * @param apikeyUpdate    containing updated registration data from the original request
     * @throws ApiKeyException when there is a failure
     */
    public void updateClient(KeycloakSecurityContext securityContext, ApiKeyRequest apikeyUpdate, String clientId) throws ApiKeyException {
        ClientRepresentation clientRepresentation = getClientRepresentation(clientId, securityContext);
        updateClient(updateClientRepresentation(clientRepresentation, apikeyUpdate), securityContext);
    }

    /**
     * Deletes a client from Keycloak
     * @param securityContext security context with access token
     * @param clientId the id of the client that is to be deleted
     * @throws ApiKeyException
     */
    public void deleteClient(KeycloakSecurityContext securityContext, String clientId) throws ApiKeyException {
        ClientRepresentation clientRepresentation = getClientRepresentation(clientId, securityContext);
        HttpDelete httpDelete = new HttpDelete(KeycloakUriBuilder
                .fromUri(String.format(CLIENTS_UPDATE_ENDPOINT, authServerUrl, realm, clientRepresentation.getId())).build());
        addAuthorizationHeader(securityContext.getAccessTokenString(), httpDelete);
        sendRequestToKeycloak(httpDelete, HttpStatus.SC_NO_CONTENT, clientRepresentation);
    }

    /**
     * Updates the client representation with the new values supplied with the update request.
     *
     * @param clientRepresentation client representation that was formerly retrieved from Keycloak
     * @param apikeyUpdate         updated registration data
     * @return changed client representation
     */
    private ClientRepresentation updateClientRepresentation(ClientRepresentation clientRepresentation, ApiKeyRequest apikeyUpdate) {
        if (apikeyUpdate == null) {
            return clientRepresentation;
        }
        clientRepresentation.setName(String.format(CLIENT_NAME
                , null != apikeyUpdate.getAppName() ? apikeyUpdate.getAppName() : clientRepresentation.getClientId()
                , null != apikeyUpdate.getCompany() ? apikeyUpdate.getCompany() : ""));
        clientRepresentation.setDescription(String.format(CLIENT_DESCRIPTION, apikeyUpdate.getFirstName(), apikeyUpdate.getLastName(),
                apikeyUpdate.getEmail()));
        return clientRepresentation;
    }

    /**
     * Performs actual call to Keycloak sending the updated client data. Only Name and Description are subject of an update. The rest will remain unchanged.
     *
     * @param clientRepresentation client representation that will be sent as request body
     * @param securityContext      security context with the access token
     * @throws ApiKeyException
     */
    private void updateClient(ClientRepresentation clientRepresentation, KeycloakSecurityContext securityContext) throws ApiKeyException {
        HttpPut httpPut = new HttpPut(KeycloakUriBuilder
                .fromUri(String.format(CLIENTS_UPDATE_ENDPOINT, authServerUrl, realm, clientRepresentation.getId())).build());
        addAuthorizationHeader(securityContext.getAccessTokenString(), httpPut);
        addRequestEntity(clientRepresentation, httpPut);
        sendRequestToKeycloak(httpPut, HttpStatus.SC_NO_CONTENT, clientRepresentation);
    }

    /**
     * Retrieve client secret from Keycloak. In order to do it client identifier (not client-id) must be retrieved first.
     * This identifier is needed when requesting the client secret.
     *
     * @param clientId        client id
     * @param securityContext security context with access token
     * @return client secret wrapped in ClientRepresentation object
     * @throws ApiKeyException when any exception happens during communication with Keycloak
     */
    private ClientRepresentation getClientSecret(String clientId, KeycloakSecurityContext securityContext) throws ApiKeyException {
        ClientRepresentation representation = getClientRepresentation(clientId, securityContext);

        HttpGet httpGet = new HttpGet(KeycloakUriBuilder
                .fromUri(String.format(CLIENT_SECRET_ENDPOINT, authServerUrl, realm, representation.getId()))
                .build());
        addAuthorizationHeader(securityContext.getAccessTokenString(), httpGet);

        String secret = null;
        LOG.debug("Sending getClientSecret to Keycloak...");
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            LOG.debug("Received getClientSecret from Keycloak");
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                throw new ApiKeyException(ERROR_COMMUNICATING_WITH_KEYCLOAK, response.getStatusLine().getReasonPhrase());
            }
            InputStream is = response.getEntity().getContent();
            secret = mapper.readValue(is, CredentialRepresentation.class).getValue();
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
    private ClientRepresentation getClientRepresentation(String clientId, KeycloakSecurityContext securityContext) throws ApiKeyException {
        HttpGet httpGet = prepareGetClientRequest(clientId, securityContext.getAccessTokenString());
        List<ClientRepresentation> clients = getClients(httpGet);
        if (clients == null || clients.isEmpty()) {
            throw new MissingKCClientException(clientId);
        }
        return clients.get(0);
    }

    private void sendRequestToKeycloak(HttpUriRequest httpRequest, int expectedHttpStatus, ClientRepresentation clientRep) throws ApiKeyException {
        LOG.debug("Sending {} request for API key {} (client {}) to Keycloak...", httpRequest.getMethod(), clientRep.getClientId(), clientRep.getId());
        try (CloseableHttpResponse response = httpClient.execute(httpRequest)) {
            LOG.debug("Received response for client {} from Keycloak: {}", clientRep.getId(), response);
            if (response.getStatusLine().getStatusCode() != expectedHttpStatus) {
                throw new ApiKeyException(ERROR_COMMUNICATING_WITH_KEYCLOAK, response.getStatusLine().getReasonPhrase());
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
     * @throws ApiKeyException
     */
    private void addRequestEntity(ClientRepresentation clientRepresentation, HttpEntityEnclosingRequestBase httpRequest) throws ApiKeyException {
        httpRequest.addHeader("Content-Type", "application/json");
        HttpEntity entity = null;
        try {
            entity = new StringEntity(mapper.writeValueAsString(clientRepresentation), "UTF-8");
        } catch (JsonProcessingException e) {
            throw new ApiKeyException("Problem with creating client representation for the request", e);
        }
        httpRequest.setEntity(entity);
    }

    /**
     * Generate a new client-id. The generated id is unique and to assure that there is a request to Keycloak to check that.
     *
     * @param securityContext security context with access token
     * @return newly generated client-id
     * @throws ApiKeyException when error occurs during check for existing clients
     */
    private String generateClientId(KeycloakSecurityContext securityContext) throws ApiKeyException {
        String newApiKey;
        PassGenerator pg = new PassGenerator();
        do {
            newApiKey = pg.generate(RandomUtils.nextInt(8, 13));
        } while (clientExists(newApiKey, securityContext.getAccessTokenString()));
        return newApiKey;
    }

    /**
     * Prepare ClientRepresentation object based on ApikeyDetails from the request.
     *
     * @param newApiKey     new api key that will be used as client-id
     * @param apikeyDetails data of the key being registered coming from the original request
     * @return ClientRepresentation object that can be used for executing create client request
     */
    private ClientRepresentation createClientRepresentation(String newApiKey, ApiKeyRequest apikeyDetails) {
        ClientRepresentation clientRepresentation = new ClientRepresentation();
        clientRepresentation.setClientId(newApiKey);
        clientRepresentation.setPublicClient(false);
        clientRepresentation.setProtocol("openid-connect");
        clientRepresentation.setName(String.format(CLIENT_NAME
                , null != apikeyDetails.getAppName() ? apikeyDetails.getAppName() : newApiKey
                , null != apikeyDetails.getCompany() ? apikeyDetails.getCompany() : ""));
        clientRepresentation.setDescription(String.format(CLIENT_DESCRIPTION, apikeyDetails.getFirstName(), apikeyDetails.getLastName(),
                apikeyDetails.getEmail()));
        clientRepresentation.setDirectAccessGrantsEnabled(false);
        clientRepresentation.setServiceAccountsEnabled(true);
        return clientRepresentation;
    }

    /**
     * Get resource authorities from the access token
     *
     * @param token access token object
     * @return collection of granted authorities to authorize resource access
     */
    Collection<GrantedAuthority> getAuthorities(AccessToken token) {
        List<GrantedAuthority> result = new ArrayList<>();
        if (useResourceRoleMappings) {
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

    /**
     * Check whether client with a given client-id exists in Keycloak
     *
     * @param newApiKey   api key to use as client-id
     * @param accessToken access token to authorize the request
     * @return true when client-id belongs to a valid client
     * @throws ApiKeyException
     */
    private boolean clientExists(String newApiKey, String accessToken) throws ApiKeyException {
        HttpGet httpGet = prepareGetClientRequest(newApiKey, accessToken);
        List<ClientRepresentation> clients = getClients(httpGet);
        return clients != null && !clients.isEmpty();
    }

    /**
     * Retrieve a list of clients using a configured get request.
     *
     * @param httpGet get request
     * @return a list of retrieved clients
     * @throws ApiKeyException
     */
    private List<ClientRepresentation> getClients(HttpGet httpGet) throws ApiKeyException {
        LOG.debug("Sending getClients to Keycloak...");
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            LOG.debug("Received getClients from Keycloak");
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                InputStream is = response.getEntity().getContent();
                CollectionType mapCollectionType = mapper.getTypeFactory()
                        .constructCollectionType(List.class, ClientRepresentation.class);
                return mapper.readValue(is, mapCollectionType);
            }
            throw new ApiKeyException(ERROR_COMMUNICATING_WITH_KEYCLOAK, response.getStatusLine().getReasonPhrase());
        } catch (IOException e) {
            throw new ApiKeyException(ERROR_COMMUNICATING_WITH_KEYCLOAK, e);
        }
    }

    /**
     * Configure get request for getting clients with client-id equal to new api key
     *
     * @param newApiKey   api key used as client-id
     * @param accessToken access token to authorize request
     * @return configured get request
     */
    private HttpGet prepareGetClientRequest(String newApiKey, String accessToken) {
        HttpGet httpGet = new HttpGet(KeycloakUriBuilder
                .fromUri(String.format(CLIENTS_ENDPOINT, authServerUrl, realm))
                .queryParam("clientId", newApiKey)
                .build());

        addAuthorizationHeader(accessToken, httpGet);
        return httpGet;
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

    /**
     * Checks whether the client for which the token was issued is the owner of the apikey
     *
     * @param apikey                      api key to check
     * @param keycloakAuthenticationToken token issued for the caller of the request
     * @return true when authorized, false otherwise
     */
    public boolean isOwner(String apikey, KeycloakAuthenticationToken keycloakAuthenticationToken) {
        if (apikey == null || keycloakAuthenticationToken == null || keycloakAuthenticationToken.getCredentials() == null) {
            return false;
        }

        // apikey parameter is the one that we want to check against the name in the authentication token
        return apikey.equals(keycloakAuthenticationToken.getName());
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

        Optional<String> manager = authorities.stream().map(GrantedAuthority::getAuthority).filter(MANAGE_CLIENTS_ROLE::equals).findFirst();
        return manager.isPresent();
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
        if (!clientRepresentation.isEnabled()) {
            clientRepresentation.setEnabled(true);
            updateClient(clientRepresentation, securityContext);
        } else {
            LOG.warn("API key {} of client {} is already enabled", clientRepresentation.getClientId(), clientRepresentation.getId());
        }
    }

    /**
     * Disables the client in Keycloak, but only if it is enabled
     *
     * @param clientId        client identifier
     * @param securityContext security context with access token
     * @throws ApiKeyException when client not found in Keycloak or update failed
     */
    public void disableClient(String clientId, KeycloakSecurityContext securityContext) throws ApiKeyException  {
        ClientRepresentation clientRepresentation = getClientRepresentation(clientId, securityContext);
        if (clientRepresentation.isEnabled()) {
            clientRepresentation.setEnabled(false);
            updateClient(clientRepresentation, securityContext);
        } else {
            LOG.warn("API key {} of client {} is already disabled", clientRepresentation.getClientId(), clientRepresentation.getId());
        }
    }
}
