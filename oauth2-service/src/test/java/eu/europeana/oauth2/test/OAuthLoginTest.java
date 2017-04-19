package eu.europeana.oauth2.test;

import eu.europeana.oauth2.AuthorizationServer;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import java.io.Serializable;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;

/**
 * Integration tests to check whether resources are secure and the OAuth2 login procedure works as expected
 * <p>
 * Created by patrick on 14-4-17.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT, classes = AuthorizationServer.class)
public class OAuthLoginTest {

    private static final Logger LOG = Logger.getLogger(OAuthLoginTest.class);

    private static final String PROTECTED_RESOURCE = "http://localhost/me";

    private static final String OAUTH_LOGIN_REQUEST = "/oauth/authorize?" +
            "client_id=unit_test&redirect_uri="+PROTECTED_RESOURCE+"&response_type=code&state=mjHhKz&scope=read";
    private static final String OAUTH_TOKEN_REQUEST = "/oauth/token?grant_type=authorization_code";
    private static final String OAUTH_TOKEN_REFRESH_REQUEST = "oauth/token?grant_type=refresh_token";

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockServer;

    /**
     * Loads the entire webapplication as mock server
     */
    @Before
    public void setup() {
        mockServer = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
        assertThat(this.mockServer).isNotNull();
    }

    /**
     * This tests if the 'me' or 'user' resource is protected (when not logged in)
     *
     * @throws Exception
     */
    @Test
    public void testAccessProtected() throws Exception {
        // asking for the resource in JSON should return a 401 (and not redirect)
        this.mockServer.perform(get("/me").accept(MediaType.parseMediaType("application/json;charset=UTF-8")))
                .andExpect(status().isUnauthorized());
        this.mockServer.perform(get("/user").accept(MediaType.parseMediaType("application/json;charset=UTF-8")))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Tests whether access to any other random resource is redirected to the login url
     *
     * @throws Exception
     */
    @Test
    public void testRedirectToLogin() throws Exception {
        MvcResult result = this.mockServer.perform(get("/this/is/test").accept(MediaType.parseMediaType("text/html;application/xhtml+xml;application/xml")))
                .andExpect(status().isFound())
                .andReturn();
        // TODO redirected url should actually be https:// and not http://
        Assert.assertEquals("http://localhost/login", result.getResponse().getRedirectedUrl());
    }

    /**
     * If cross-site request forgery is enabled then all forms will have a hidden csrf input. We need to extract and post
     * the value when submitting the form
     * @param htmlForm
     * @return csrf-value or null if we couldn't find it
     */
    private String extractCsrfValue (String htmlForm) {
        String result = null;
        Pattern pattern = Pattern.compile("<input.*?name=['\"]_csrf['\"].*?value=['\"](.*?)['\"].*/>");
        Matcher matcher = pattern.matcher(htmlForm);
        if (matcher.find()) {
            LOG.debug("Found group = " + matcher.group().toString());
            result = matcher.group(1);
            LOG.info("Found CSRF token value = " + result);
        } else
        {
            LOG.warn("CSRF token value not found!");
        }
        return result;
    }

    /**
     * This tests the entire OAuth2 authentication flow as we use it most commonly (clientApp requests resource, a login
     * page is shown to the user, user logs in, approval page is shown and user accepts this).
     *
     * @throws Exception
     */
    @Test
    public void testUserLogin() throws Exception {
        // we store the session after each step and inject it when doing the next step (necessary for csrf-token validation)
        MockHttpSession session = null;
        String nextUrl = null;

        //TODO for now each expected url starts with http:// but we this should be https://. However this is not implemented yet

        // step 1. Mimick client getting secure resource, this starts authorization (should redirect to login, status 302)
        MvcResult result = this.mockServer.perform(get(OAUTH_LOGIN_REQUEST)
                    .accept(MediaType.TEXT_HTML))
                .andDo(print())
                .andExpect(status().isFound())
                .andReturn();
        session = (MockHttpSession) result.getRequest().getSession();
        nextUrl = result.getResponse().getRedirectedUrl();
        Assert.assertEquals("http://localhost/login", nextUrl);

        // step 2. Get the login page, it should be readily accessible (status 200)
        result = this.mockServer.perform(get(nextUrl)
                    .accept(MediaType.TEXT_HTML)
                    .session(session))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        String csrfValue = this.extractCsrfValue(result.getResponse().getContentAsString());
        session = (MockHttpSession) result.getRequest().getSession();

        // step 3. Post user login data (should redirect to authorization, status 302)
        // Note that we also must submit the csrf token! (unless csrf is turned off)
        result = this.mockServer.perform(post(nextUrl)
                    .contentType(MediaType.TEXT_HTML.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.TEXT_HTML)
                    .param("username", "unit_tester")
                    .param("password", "test")
                    .param("_csrf", csrfValue)
                    .session(session))
                .andDo(print())
                .andExpect(status().isFound())
                .andReturn();
        session = (MockHttpSession) result.getRequest().getSession();
        nextUrl = result.getResponse().getRedirectedUrl();
        Assert.assertTrue(nextUrl.startsWith("http://localhost/oauth/authorize"));

        // step 4. Retry the authorization request (show the authorize page, status 200)
        result = this.mockServer.perform(get(nextUrl)
                    .accept(MediaType.TEXT_HTML)
                    .session(session))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        session = (MockHttpSession) result.getRequest().getSession();
        nextUrl = result.getResponse().getForwardedUrl();

        // step 4b. The get in step 4 gives us a forwardUrl so we need retrieve that page first
        result = this.mockServer.perform(get(nextUrl)
                    .accept(MediaType.TEXT_HTML)
                    .session(session))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        csrfValue = this.extractCsrfValue(result.getResponse().getContentAsString());

        // TODO instead of hard-coded address where to post, extract this from the form (action)

        // step 5. Post the authorize data (should redirect to the requested resource, status 302)
        result = this.mockServer.perform(post("/oauth/authorize")
                .contentType(MediaType.TEXT_HTML.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.TEXT_HTML)
                    .param("user_oauth_approval", "true")
                    .param("scope.read", "true")
                    .param("authorize", "Authorize")
                    .param("_csrf", csrfValue)
                    .session(session))
                .andDo(print())
                .andExpect(status().isFound())
                .andReturn();
        session = (MockHttpSession) result.getRequest().getSession();
        nextUrl = result.getResponse().getRedirectedUrl();
        //we should now have access to the requested resource
        Assert.assertTrue(nextUrl.startsWith(PROTECTED_RESOURCE+"?"));
        String codeAndState = nextUrl.split("\\?")[1];
        LOG.info("Code and state = "+codeAndState);

        // step 6. Request a token
        //TODO figure out why we have to use authentication via header and supplying clientId and secret as parameter doesn't work
        byte[] encodedClientCredentials = Base64.encodeBase64("unit_test:test".getBytes());
        result = this.mockServer.perform(post(OAUTH_TOKEN_REQUEST+"&"+codeAndState)
                    .accept(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Basic "+new String(encodedClientCredentials))
//                    .param("client_id", "unit_test")
//                    .param("client_secret", "test")
//                    .param("username", "unit_tester")
//                    .param("password", "test")
                    .param("redirect_uri", PROTECTED_RESOURCE)
                    .param("scope", "read")
                    .session(session))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists())
                .andReturn();
        session = (MockHttpSession) result.getRequest().getSession();
        JSONObject jsonResponse = new JSONObject (result.getResponse().getContentAsString());
        String accessToken = jsonResponse.get("access_token").toString();
        LOG.info("OAuth2 access token = "+accessToken);

        // step 7. check if we can access the requested resource with our token
        // Note that we do not reuse the session here!
        result = this.mockServer.perform(get(nextUrl)
                    .accept(MediaType.APPLICATION_JSON)
                    .param("access_token", accessToken)
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        session = (MockHttpSession) result.getRequest().getSession();

    }



}
