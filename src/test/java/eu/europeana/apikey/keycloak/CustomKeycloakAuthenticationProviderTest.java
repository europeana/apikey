package eu.europeana.apikey.keycloak;

import eu.europeana.apikey.TestResources;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.representations.AccessToken;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@RunWith(MockitoJUnitRunner.class)
//@RunWith(SpringJUnit4ClassRunner.class)
//@Ignore
public class CustomKeycloakAuthenticationProviderTest {

    @Mock
    private final KeycloakClientManager keycloakClientManager = new KeycloakClientManager(TestResources.getKeycloakProperties());

    @InjectMocks
    private CustomKeycloakAuthenticationProvider authenticationProvider;

//    @Test
    public void authenticateOKWithResourceRoleMappings() {
        Authentication          authentication  = new UsernamePasswordAuthenticationToken(TestResources.getManagerClientId(),
                                                                                          TestResources.getManagerClientSecret());
        KeycloakSecurityContext securityContext = prepareForResourceRoleMappings();

        Authentication authenticatedToken = authenticationProvider.authenticate(authentication);

        Assert.assertNotNull(authenticatedToken);
        Assert.assertTrue(authenticatedToken instanceof KeycloakAuthenticationToken);
        Assert.assertNotNull(authenticatedToken.getPrincipal());
        Assert.assertEquals(TestResources.getManagerClientId(), ((KeycloakPrincipal) authenticatedToken.getPrincipal()).getName());
        Assert.assertNotNull(authenticatedToken.getDetails());
        Assert.assertEquals(TestResources.getManagerClientId(), authenticatedToken.getDetails());
        Assert.assertEquals(securityContext, authenticatedToken.getCredentials());
        Assert.assertNotNull(authenticatedToken.getAuthorities());
        Assert.assertFalse(authenticatedToken.getAuthorities().isEmpty());
        Assert.assertEquals(1, authenticatedToken.getAuthorities().size());
        Assert.assertEquals(TestResources.getRoleCreateClient(), authenticatedToken.getAuthorities().iterator().next().getAuthority());
        Assert.assertNotNull(authenticatedToken.getCredentials());
        Assert.assertEquals(securityContext, authenticatedToken.getCredentials());
    }

    private KeycloakSecurityContext prepareForResourceRoleMappings() {
        ReflectionTestUtils.setField(keycloakClientManager, "useResourceRoleMappings", true);
        KeycloakSecurityContext                    securityContext = Mockito.mock(KeycloakSecurityContext.class);
        KeycloakPrincipal<KeycloakSecurityContext> principal       = new KeycloakPrincipal<>(TestResources.getManagerClientId(),
                                                                                             securityContext);
        AccessToken                                accessToken     = Mockito.mock(AccessToken.class);
        Mockito.when(securityContext.getAccessToken()).thenReturn(accessToken);
        Map<String, AccessToken.Access> accessMap = new HashMap<>();
        AccessToken.Access              access    = Mockito.mock(AccessToken.Access.class);
        accessMap.put(TestResources.getResourceAccess(), access);
        Set<String> roles = new HashSet<>();
        roles.add(TestResources.getRoleCreateClient());
        Mockito.when(access.getRoles()).thenReturn(roles);
        Mockito.when(accessToken.getResourceAccess()).thenReturn(accessMap);
        Mockito.when(keycloakClientManager.authenticateClient(Mockito.anyString(), Mockito.anyString()))
               .thenReturn(principal);
        Mockito.when(keycloakClientManager.getAuthorities(Mockito.any(AccessToken.class))).thenCallRealMethod();
        return securityContext;
    }

//    @Test
    public void authenticateOKWithoutResourceRoleMappings() {
        Authentication          authentication  = new UsernamePasswordAuthenticationToken(TestResources.getManagerClientId(),
                                                                                          TestResources.getManagerClientSecret());
        KeycloakSecurityContext securityContext = prepareForRealmAccess();

        Authentication authenticatedToken = authenticationProvider.authenticate(authentication);

        Assert.assertNotNull(authenticatedToken);
        Assert.assertTrue(authenticatedToken instanceof KeycloakAuthenticationToken);
        Assert.assertNotNull(authenticatedToken.getPrincipal());
        Assert.assertEquals(TestResources.getManagerClientId(), ((KeycloakPrincipal) authenticatedToken.getPrincipal()).getName());
        Assert.assertNotNull(authenticatedToken.getDetails());
        Assert.assertEquals(TestResources.getManagerClientId(), authenticatedToken.getDetails());
        Assert.assertEquals(securityContext, authenticatedToken.getCredentials());
        Assert.assertNotNull(authenticatedToken.getAuthorities());
        Assert.assertFalse(authenticatedToken.getAuthorities().isEmpty());
        Assert.assertEquals(1, authenticatedToken.getAuthorities().size());
        Assert.assertEquals(TestResources.getRoleCreateClient(), authenticatedToken.getAuthorities().iterator().next().getAuthority());
        Assert.assertNotNull(authenticatedToken.getCredentials());
        Assert.assertEquals(securityContext, authenticatedToken.getCredentials());
    }

    private KeycloakSecurityContext prepareForRealmAccess() {
        ReflectionTestUtils.setField(keycloakClientManager, "useResourceRoleMappings", false);
        KeycloakSecurityContext                    securityContext = Mockito.mock(KeycloakSecurityContext.class);
        KeycloakPrincipal<KeycloakSecurityContext> principal       = new KeycloakPrincipal<>(TestResources.getManagerClientId(),
                                                                                             securityContext);
        AccessToken                                accessToken     = Mockito.mock(AccessToken.class);
        Mockito.when(securityContext.getAccessToken()).thenReturn(accessToken);
        AccessToken.Access access = Mockito.mock(AccessToken.Access.class);
        Set<String>        roles  = new HashSet<>();
        roles.add(TestResources.getRoleCreateClient());
        Mockito.when(access.getRoles()).thenReturn(roles);
        Mockito.when(accessToken.getRealmAccess()).thenReturn(access);
        Mockito.when(keycloakClientManager.authenticateClient(Mockito.anyString(), Mockito.anyString()))
               .thenReturn(principal);
        Mockito.when(keycloakClientManager.getAuthorities(Mockito.any(AccessToken.class))).thenCallRealMethod();
        return securityContext;
    }

    @Test
    public void authenticateFailed() {
        Authentication authentication = new UsernamePasswordAuthenticationToken(TestResources.getManagerClientId(),
                                                                                TestResources.getManagerClientSecret());
        Mockito.when(keycloakClientManager.authenticateClient(Mockito.anyString(), Mockito.anyString())).thenReturn(null);

        Authentication authenticatedToken = authenticationProvider.authenticate(authentication);

        Assert.assertNull(authenticatedToken);
    }
}