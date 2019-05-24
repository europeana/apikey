package eu.europeana.apikey.keycloak;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.representations.AccessToken;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@RunWith(SpringJUnit4ClassRunner.class)
public class CustomKeycloakAuthenticationProviderTest {

    private static final String MANAGER_CLIENT_ID = "manager";

    private static final String MANAGER_CLIENT_SECRET = "secret";

    private static final String ROLE_CREATE_CLIENT = "realm-create-client";

    private static final String RESOURCE_ACCESS = "access";

    @Mock
    private KeycloakManager keycloakManager;

    @InjectMocks
    private CustomKeycloakAuthenticationProvider authenticationProvider;

    @Test
    public void authenticateOKWithResourceRoleMappings() {
        Authentication authentication = new UsernamePasswordAuthenticationToken(MANAGER_CLIENT_ID, MANAGER_CLIENT_SECRET);
        KeycloakSecurityContext securityContext = prepareForResourceRoleMappings();

        Authentication authenticatedToken = authenticationProvider.authenticate(authentication);

        Assert.assertNotNull(authenticatedToken);
        Assert.assertTrue(authenticatedToken instanceof KeycloakAuthenticationToken);
        Assert.assertNotNull(authenticatedToken.getPrincipal());
        Assert.assertEquals(MANAGER_CLIENT_ID, ((KeycloakPrincipal)authenticatedToken.getPrincipal()).getName());
        Assert.assertNotNull(authenticatedToken.getDetails());
        Assert.assertEquals(MANAGER_CLIENT_ID, authenticatedToken.getDetails());
        Assert.assertEquals(securityContext, authenticatedToken.getCredentials());
        Assert.assertNotNull(authenticatedToken.getAuthorities());
        Assert.assertFalse(authenticatedToken.getAuthorities().isEmpty());
        Assert.assertEquals(1, authenticatedToken.getAuthorities().size());
        Assert.assertEquals(ROLE_CREATE_CLIENT, authenticatedToken.getAuthorities().iterator().next().getAuthority());
        Assert.assertNotNull(authenticatedToken.getCredentials());
        Assert.assertEquals(securityContext, authenticatedToken.getCredentials());
    }

    private KeycloakSecurityContext prepareForResourceRoleMappings() {
        ReflectionTestUtils.setField(keycloakManager,"useResourceRoleMappings", true);
        KeycloakSecurityContext securityContext = Mockito.mock(KeycloakSecurityContext.class);
        KeycloakPrincipal<KeycloakSecurityContext> principal = new KeycloakPrincipal<>(MANAGER_CLIENT_ID, securityContext);
        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(securityContext.getAccessToken()).thenReturn(accessToken);
        Map<String, AccessToken.Access> accessMap = new HashMap<>();
        AccessToken.Access access = Mockito.mock(AccessToken.Access.class);
        accessMap.put(RESOURCE_ACCESS, access);
        Set<String> roles = new HashSet<>();
        roles.add(ROLE_CREATE_CLIENT);
        Mockito.when(access.getRoles()).thenReturn(roles);
        Mockito.when(accessToken.getResourceAccess()).thenReturn(accessMap);
        Mockito.when(keycloakManager.authenticateClient(Mockito.anyString(), Mockito.anyString())).thenReturn(principal);
        Mockito.when(keycloakManager.getAuthorities(Mockito.any(AccessToken.class))).thenCallRealMethod();
        return securityContext;
    }
    @Test
    public void authenticateOKWithoutResourceRoleMappings() {
        Authentication authentication = new UsernamePasswordAuthenticationToken(MANAGER_CLIENT_ID, MANAGER_CLIENT_SECRET);
        KeycloakSecurityContext securityContext = prepareForRealmAccess();

        Authentication authenticatedToken = authenticationProvider.authenticate(authentication);

        Assert.assertNotNull(authenticatedToken);
        Assert.assertTrue(authenticatedToken instanceof KeycloakAuthenticationToken);
        Assert.assertNotNull(authenticatedToken.getPrincipal());
        Assert.assertEquals(MANAGER_CLIENT_ID, ((KeycloakPrincipal)authenticatedToken.getPrincipal()).getName());
        Assert.assertNotNull(authenticatedToken.getDetails());
        Assert.assertEquals(MANAGER_CLIENT_ID, authenticatedToken.getDetails());
        Assert.assertEquals(securityContext, authenticatedToken.getCredentials());
        Assert.assertNotNull(authenticatedToken.getAuthorities());
        Assert.assertFalse(authenticatedToken.getAuthorities().isEmpty());
        Assert.assertEquals(1, authenticatedToken.getAuthorities().size());
        Assert.assertEquals(ROLE_CREATE_CLIENT, authenticatedToken.getAuthorities().iterator().next().getAuthority());
        Assert.assertNotNull(authenticatedToken.getCredentials());
        Assert.assertEquals(securityContext, authenticatedToken.getCredentials());
    }

    private KeycloakSecurityContext prepareForRealmAccess() {
        ReflectionTestUtils.setField(keycloakManager,"useResourceRoleMappings", false);
        KeycloakSecurityContext securityContext = Mockito.mock(KeycloakSecurityContext.class);
        KeycloakPrincipal<KeycloakSecurityContext> principal = new KeycloakPrincipal<>(MANAGER_CLIENT_ID, securityContext);
        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(securityContext.getAccessToken()).thenReturn(accessToken);
        AccessToken.Access access = Mockito.mock(AccessToken.Access.class);
        Set<String> roles = new HashSet<>();
        roles.add(ROLE_CREATE_CLIENT);
        Mockito.when(access.getRoles()).thenReturn(roles);
        Mockito.when(accessToken.getRealmAccess()).thenReturn(access);
        Mockito.when(keycloakManager.authenticateClient(Mockito.anyString(), Mockito.anyString())).thenReturn(principal);
        Mockito.when(keycloakManager.getAuthorities(Mockito.any(AccessToken.class))).thenCallRealMethod();
        return securityContext;
    }

    @Test
    public void authenticateFailed() {
        Authentication authentication = new UsernamePasswordAuthenticationToken(MANAGER_CLIENT_ID, MANAGER_CLIENT_SECRET);
        Mockito.when(keycloakManager.authenticateClient(Mockito.anyString(), Mockito.anyString())).thenReturn(null);

        Authentication authenticatedToken = authenticationProvider.authenticate(authentication);

        Assert.assertNull(authenticatedToken);
    }
}