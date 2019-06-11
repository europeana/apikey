package eu.europeana.apikey.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import eu.europeana.apikey.domain.*;
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
    private static final Logger LOG   = LogManager.getLogger(KeycloakManager.class);

    /** Template for client name */
    private static final String CLIENT_NAME = "%s (%s)";

    /** Template for client description */
    private static final String CLIENT_DESCRIPTION = "%s %s (%s)";

    /** Template for clients endpoint */
    private static final String CLIENTS_ENDPOINT = "%s/admin/realms/%s/clients";

    /** Template for client-secret endpoint */
    private static final String CLIENT_SECRET_ENDPOINT = "%s/admin/realms/%s/clients/%s/client-secret";

    /** Template for clients update endpoint */
    private static final String CLIENTS_UPDATE_ENDPOINT = "%s/admin/realms/%s/clients/%s";

    /** Role for managing clients used to authorize access by Manager Client */
    private static final String MANAGE_CLIENTS_ROLE = "manage-clients";

    private static final String ERROR_COMMUNICATING_WITH_KEYCLOAK = "Error communicating with Keycloak";

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.use-resource-role-mappings}")
    private boolean useResourceRoleMappings;

    /** Http client used for communicating with Keycloak where Keycloak admin client is not appropriate */
    private CloseableHttpClient httpClient;

    /** Object mapper used for serialization and deserialization Keycloak objects to / from json */
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
     * @param clientId client-id of the client executing the request
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

        AccessTokenResponse token = getAccessToken(keycloak);
        if (token == null) {
            return null;
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
     * @param apikeyCreate object containing registration data from the original request
     * @return new Apikey object with all necessary fields.
     * @throws ApikeyException when there is a failure
     */
    public FullApikey createClient(KeycloakSecurityContext securityContext, ApikeyDetails apikeyCreate) throws ApikeyException {
        // ClientId must be unique
        String newApiKey = generateClientId(securityContext);

        // create client in Keycloak
        createClient(
                createClientRepresentation(newApiKey, apikeyCreate),
                securityContext);

        // create DB entity
        FullApikey apikey = new FullApikey(newApiKey,
                apikeyCreate.getFirstName(),
                apikeyCreate.getLastName(),
                apikeyCreate.getEmail(), getClientSecret(newApiKey, securityContext));
        if (null != apikeyCreate.getWebsite()) {
            apikey.setWebsite(apikeyCreate.getWebsite());
        }
        if (null != apikeyCreate.getAppName()) {
            apikey.setAppName(apikeyCreate.getAppName());
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
     * @param apikeyUpdate containing updated registration data from the original request
     * @throws ApikeyException when there is a failure
     */
    public void updateClient(KeycloakSecurityContext securityContext, ApikeyDetails apikeyUpdate, String clientId) throws ApikeyException {
        ClientRepresentation clientRepresentation = getClientRepresentation(clientId, securityContext);
        if (clientRepresentation == null) {
           throw new ApikeyException(HttpStatus.SC_NOT_FOUND);
        }
        updateClient(updateClientRepresentation(clientRepresentation, apikeyUpdate), securityContext);
    }

    /**
     * Updates the client representation with the new values supplied with the update request.
     *
     * @param clientRepresentation client representation that was formerly retrieved from Keycloak
     * @param apikeyUpdate updated registration data
     * @return changed client representation
     */
    private ClientRepresentation updateClientRepresentation(ClientRepresentation clientRepresentation, ApikeyDetails apikeyUpdate) {
        if (apikeyUpdate == null) {
            return clientRepresentation;
        }
        clientRepresentation.setName(String.format(CLIENT_NAME
                , null != apikeyUpdate.getAppName() ? apikeyUpdate.getAppName() : clientRepresentation.getClientId()
                , null != apikeyUpdate.getCompany() ? apikeyUpdate.getCompany() : ""));
        clientRepresentation.setDescription(String.format(CLIENT_DESCRIPTION, apikeyUpdate.getFirstName(), apikeyUpdate.getLastName(), apikeyUpdate.getEmail()));
        return clientRepresentation;
    }

    /**
     * Performs actual call to Keycloak sending the updated client data. Only Name and Description are subject of an update. The rest will remain unchanged.
     *
     * @param clientRepresentation client representation that will be sent as request body
     * @param securityContext security context with the access token
     * @throws ApikeyException
     */
    private void updateClient(ClientRepresentation clientRepresentation, KeycloakSecurityContext securityContext) throws ApikeyException {
        HttpPut httpPut = preparePutClientRequest(clientRepresentation, securityContext.getAccessTokenString());
        CloseableHttpResponse response = null;
        try {
            response = httpClient.execute(httpPut);
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_NO_CONTENT) {
                throw new ApikeyException(response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase(), response.getStatusLine().getReasonPhrase());
            }
        } catch (IOException e) {
            LOG.error(ERROR_COMMUNICATING_WITH_KEYCLOAK, e);
            throw new ApikeyException(500, ERROR_COMMUNICATING_WITH_KEYCLOAK, e.getMessage());
        }
        finally {
            if (null != response) {
                try {
                    response.close();
                } catch (IOException e) {
                    LOG.error("Response close failed", e);
                }
            }
        }
    }

    /**
     * Retrieve client secret from Keycloak. In order to do it client identifier (not client-id) must be retrieved first.
     * This identifier is needed when requesting the client secret.
     *
     * @param clientId client id
     * @param securityContext security context with access token
     * @return client secret
     * @throws ApikeyException when any exception happens during communication with Keycloak
     */
    private String getClientSecret(String clientId, KeycloakSecurityContext securityContext) throws ApikeyException {
        ClientRepresentation representation = getClientRepresentation(clientId, securityContext);
        if (representation == null) {
            return null;
        }
        HttpGet httpGetSecret = prepareGetClientSecretRequest(representation.getId(), securityContext.getAccessTokenString());
        return getClientSecret(httpGetSecret);
    }

    /**
     * Retrieve client secret from Keycloak. In order to do it client identifier (not client-id) must be retrieved first.
     * This identifier is needed when requesting the client secret.
     *
     * @param clientId client id
     * @param securityContext security context with access token
     * @return client secret
     * @throws ApikeyException when any exception happens during communication with Keycloak
     */
    private ClientRepresentation getClientRepresentation(String clientId, KeycloakSecurityContext securityContext) throws ApikeyException {
        HttpGet httpGet = prepareGetClientRequest(clientId, securityContext.getAccessTokenString());
        List<ClientRepresentation> clients = getClients(httpGet);
        if (clients == null || clients.isEmpty()) {
            return null;
        }
        return clients.get(0);
    }

    /**
     * Retrieve client secret from Keycloak. In case of any problems communicating with Keycloak exception is thrown.
     * @param httpGet get request prepared for the specific client
     * @return client secret
     * @throws ApikeyException when any problem occurs
     */
    private String getClientSecret(HttpGet httpGet) throws ApikeyException {
        try {
            CloseableHttpResponse response = httpClient.execute(httpGet);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                InputStream is = response.getEntity().getContent();
                return mapper.readValue(is, CredentialRepresentation.class).getValue();
            }
            throw new ApikeyException(response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
        } catch (IOException e) {
            LOG.error(ERROR_COMMUNICATING_WITH_KEYCLOAK, e);
            throw new ApikeyException(500, ERROR_COMMUNICATING_WITH_KEYCLOAK, e.getMessage());
        }
    }

    /**
     * Create a get request for retrieving client secret.
     * @param id client identifier
     * @param accessToken access token use to authorize this request
     * @return configured get request
     */
    private HttpGet prepareGetClientSecretRequest(String id, String accessToken) {
        HttpGet httpGet = new HttpGet(KeycloakUriBuilder
                .fromUri(String.format(CLIENT_SECRET_ENDPOINT, authServerUrl, realm, id))
                .build());

        addAuthorizationHeader(accessToken, httpGet);
        return httpGet;
    }

    /**
     * Create a new client in Keycloak using client representation. Current access token will be used for this request.
     *
     * @param clientRepresentation ClientRepresentation of the client as specified in Admin REST API docs
     * @param securityContext security context with current access token
     * @throws ApikeyException if any exception happens while executing the request
     */
    private void createClient(ClientRepresentation clientRepresentation, KeycloakSecurityContext securityContext) throws ApikeyException {
        HttpPost httpPost = preparePostClientRequest(clientRepresentation, securityContext.getAccessTokenString());
        CloseableHttpResponse response = null;
        try {
            response = httpClient.execute(httpPost);
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_CREATED) {
                throw new ApikeyException(response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase(), response.getStatusLine().getReasonPhrase());
            }
        } catch (IOException e) {
            LOG.error(ERROR_COMMUNICATING_WITH_KEYCLOAK, e);
            throw new ApikeyException(500, ERROR_COMMUNICATING_WITH_KEYCLOAK, e.getMessage());
        }
        finally {
            if (null != response) {
                try {
                    response.close();
                } catch (IOException e) {
                    LOG.error("Response close failed", e);
                }
            }
        }
    }

    /**
     * Prepare post request for creating a new client. Client representation is serialized to json and placed in request body.
     * Access token is put to the Authorization header.
     *
     * @param clientRepresentation client representation to place in the request body
     * @param accessToken access token for authorization
     * @return created request that can be used with the http client
     * @throws ApikeyException when client representation could not be correctly serialized to json
     */
    private HttpPost preparePostClientRequest(ClientRepresentation clientRepresentation, String accessToken) throws ApikeyException {
        HttpPost httpPost = new HttpPost(KeycloakUriBuilder
                .fromUri(String.format(CLIENTS_ENDPOINT, authServerUrl, realm)).build());
        addAuthorizationHeader(accessToken, httpPost);
        addRequestEntity(clientRepresentation, httpPost);
        return httpPost;
    }

    /**
     * Prepare post request for creating a new client. Client representation is serialized to json and placed in request body.
     * Access token is put to the Authorization header.
     *
     * @param clientRepresentation client representation to place in the request body
     * @param accessToken access token for authorization
     * @return created request that can be used with the http client
     * @throws ApikeyException when client representation could not be correctly serialized to json
     */
    private HttpPut preparePutClientRequest(ClientRepresentation clientRepresentation, String accessToken) throws ApikeyException {
        HttpPut httpPut = new HttpPut(KeycloakUriBuilder
                .fromUri(String.format(CLIENTS_UPDATE_ENDPOINT, authServerUrl, realm, clientRepresentation.getId())).build());
        addAuthorizationHeader(accessToken, httpPut);
        addRequestEntity(clientRepresentation, httpPut);
        return httpPut;
    }

    /**
     * Adds body to the request. The body is ClientRepresentation in json.
     *
     * @param clientRepresentation representation of the clinet to be sent to Keycloak
     * @param httpRequest request to which the body will be attached
     * @throws ApikeyException
     */
    private void addRequestEntity(ClientRepresentation clientRepresentation, HttpEntityEnclosingRequestBase httpRequest) throws ApikeyException {
        httpRequest.addHeader("Content-Type", "application/json");
        HttpEntity entity = null;
        try {
            entity = new StringEntity(mapper.writeValueAsString(clientRepresentation), "UTF-8");
        } catch (JsonProcessingException e) {
            throw new ApikeyException(400, "Problem with creating client representation for the request", e.getMessage());
        }
        httpRequest.setEntity(entity);
    }

    /**
     * Generate a new client-id. The generated id is unique and to assure that there is a request to Keycloak to check that.
     * @param securityContext security context with access token
     * @return newly generated client-id
     * @throws ApikeyException when error occurs during check for existing clients
     */
    private String generateClientId(KeycloakSecurityContext securityContext) throws ApikeyException {
        String newApiKey;
        PassGenerator pg = new PassGenerator();
        do {
            newApiKey = pg.generate(RandomUtils.nextInt(8, 13));
        } while (clientExists(newApiKey, securityContext.getAccessTokenString()));
        return newApiKey;
    }

    /**
     * Prepare ClientRepresentation object based on ApikeyDetails from the request.
     * @param newApiKey new api key that will be used as client-id
     * @param apikeyDetails data of the key being registered coming from the original request
     * @return ClientRepresentation object that can be used for executing create client request
     */
    private ClientRepresentation createClientRepresentation(String newApiKey, ApikeyDetails apikeyDetails) {
        ClientRepresentation clientRepresentation = new ClientRepresentation();
        clientRepresentation.setClientId(newApiKey);
        clientRepresentation.setPublicClient(false);
        clientRepresentation.setProtocol("openid-connect");
        clientRepresentation.setName(String.format(CLIENT_NAME
                , null != apikeyDetails.getAppName() ? apikeyDetails.getAppName() : newApiKey
                , null != apikeyDetails.getCompany() ? apikeyDetails.getCompany() : ""));
        clientRepresentation.setDescription(String.format(CLIENT_DESCRIPTION, apikeyDetails.getFirstName(), apikeyDetails.getLastName(), apikeyDetails.getEmail()));
        clientRepresentation.setDirectAccessGrantsEnabled(false);
        return clientRepresentation;
    }

    /**
     * Get resource authorities from the access token
     * @param token access token object
     * @return collection of granted authorities to authorize resource access
     */
    Collection<? extends GrantedAuthority> getAuthorities(AccessToken token) {
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
     * Get access token string from the Keycloak admin client
     * @param keycloak admin client
     * @return access token string
     */
    private AccessTokenResponse getAccessToken(Keycloak keycloak) {
        try {
            return keycloak.tokenManager().getAccessToken();
        } catch (Exception anyException) {
            LOG.error("Retrieving access token failed", anyException);
            return null;
        }
    }

    /**
     * Check whether client with a given client-id exists in Keycloak
     * @param newApiKey api key to use as client-id
     * @param accessToken access token to authorize the request
     * @return true when client-id belongs to a valid client
     * @throws ApikeyException
     */
    private boolean clientExists(String newApiKey, String accessToken) throws ApikeyException {
        HttpGet httpGet = prepareGetClientRequest(newApiKey, accessToken);
        List<ClientRepresentation> clients = getClients(httpGet);
        return clients != null && !clients.isEmpty();
    }

    /**
     * Retrieve a list of clients using a configured get request.
     * @param httpGet get request
     * @return a list of retrieved clients
     * @throws ApikeyException
     */
    private List<ClientRepresentation> getClients(HttpGet httpGet) throws ApikeyException {
        try {
            CloseableHttpResponse response = httpClient.execute(httpGet);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                InputStream is = response.getEntity().getContent();
                CollectionType mapCollectionType = mapper.getTypeFactory()
                        .constructCollectionType(List.class, ClientRepresentation.class);
                return mapper.readValue(is, mapCollectionType);
            }
            throw new ApikeyException(response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
        } catch (IOException e) {
            LOG.error(ERROR_COMMUNICATING_WITH_KEYCLOAK, e);
            throw new ApikeyException(500, ERROR_COMMUNICATING_WITH_KEYCLOAK, e.getMessage());
        }
    }

    /**
     * Configure get request for getting clients with client-id equal to new api key
     * @param newApiKey api key used as client-id
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
     * @param accessToken access token to put in the header
     * @param request request to which the header will be added
     */
    private void addAuthorizationHeader(String accessToken, HttpRequestBase request) {
        request.addHeader("Authorization", "bearer " + accessToken);
    }

    /**
     * Checks whether the client for which the token was issued is the owner of the apikey or a manager client
     * @param apikey api key to check
     * @param keycloakAuthenticationToken token issued for the caller of the request
     * @return true when authorized, false otherwise
     */
    public boolean isClientAuthorized(String apikey, KeycloakAuthenticationToken keycloakAuthenticationToken, boolean managerOnly) {
        if (apikey == null || keycloakAuthenticationToken == null || keycloakAuthenticationToken.getCredentials() == null) {
            return false;
        }

        if (!managerOnly && apikey.equals(keycloakAuthenticationToken.getName())) {
            // apikey parameter is the one that we want to check against the name in the authentication token
            return true;
        }

        Collection<GrantedAuthority> authorities = keycloakAuthenticationToken.getAuthorities();
        if (authorities == null || authorities.isEmpty()) {
            return false;
        }

        Optional<String> manager = authorities.stream().map(GrantedAuthority::getAuthority).filter(MANAGE_CLIENTS_ROLE::equals).findFirst();
        return manager.isPresent();
    }

    /**
     * Enable / disable the client in Keycloak. If the status of the client wouldn't change after the update the call to Keycloak is skipped.
     *
     * @param enable enable or disable a client
     * @param clientId client identifier
     * @param apikeyUpdate update information which will be used in case of enabling
     * @param securityContext security context with access token
     * @throws ApikeyException when client not found in Keycloak or update failed
     */
    public void enableClient(boolean enable, String clientId, ApikeyDetails apikeyUpdate, KeycloakSecurityContext securityContext) throws ApikeyException {
        ClientRepresentation clientRepresentation = getClientRepresentation(clientId, securityContext);
        if (clientRepresentation == null) {
            throw new ApikeyException(HttpStatus.SC_NOT_FOUND);
        }
        if (clientRepresentation.isEnabled() != enable) {
            if (enable) {
                updateClientRepresentation(clientRepresentation, apikeyUpdate);
            }
            clientRepresentation.setEnabled(enable);
            updateClient(clientRepresentation, securityContext);
        }
    }
}
