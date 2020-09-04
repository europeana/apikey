package eu.europeana.apikey.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.europeana.apikey.ApiKeyApplication;
import eu.europeana.apikey.captcha.CaptchaManager;
import eu.europeana.apikey.domain.ApiKey;
import eu.europeana.apikey.domain.ApiKeyRequest;
import eu.europeana.apikey.domain.ApiKeySecret;
import eu.europeana.apikey.exception.ApiKeyException;
import eu.europeana.apikey.keycloak.*;
import eu.europeana.apikey.mail.MailService;
import eu.europeana.apikey.repos.ApiKeyRepo;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.Base64Utils;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Optional;

import static org.junit.Assert.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

@RunWith(SpringRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = ApiKeyApplication.class)
@TestPropertySource(locations = "classpath:apikey-test.properties")
public class ApiKeyControllerTest {

    private static final String EXISTING_API_KEY_1   = "apikey1";
    private static final String EXISTING_API_KEY_2   = "apikey2";
    private static final String UNREGISTERED_API_KEY = "apikey3";
    private static final String DEPRECATED_API_KEY   = "apikey4";
    private static final String NEW_API_KEY          = "apikey5";
    private static final String CAPTCHA_API_KEY      = "apikey6";
    private static final String MIGRATE_API_KEY      = "to-migrate";
    private static final String NON_EXISTIG_API_KEY  = "testing";
    private static final String NEW_KEYCLOACKID      = "apikey7";

    private static final String CLIENT_ID            = "client";
    private static final String CLIENT_SECRET        = "secret";

    private static final String ACCESS_TOKEN_STRING  = "token1";
    private static final String NEW_CLIENT_SECRET    = "134d4ec9-a26e-4dcb-93b7-13e22606eb9d";

    @Autowired
    private ApiKeyRepo apiKeyRepo;

    @Mock
    private CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;

    @Mock
    private CaptchaManager captchaManager;

    @Mock
    private MailService emailService;

    @Mock
    private SimpleMailMessage apiKeyCreatedMail;

    @Mock
    private KeycloakManager keycloakManager;

    private MockMvc mvc;
    private ApiKeyController apiKeyController;
    private ApiKeyRequest    createApiKeyRequest;
    private ApiKeyRequest    captchaApiKeyRequest;
    private ApiKeyRequest    updatedApiKeyRequest;

    @Before
    public void setup() {

        apiKeyController = Mockito.spy(new ApiKeyController(apiKeyRepo, captchaManager, customKeycloakAuthenticationProvider, emailService, apiKeyCreatedMail, keycloakManager));
        ReflectionTestUtils.setField(apiKeyController, "managerClientId", CLIENT_ID);
        ReflectionTestUtils.setField(apiKeyController, "managerClientSecret", CLIENT_SECRET);

        mvc = MockMvcBuilders
                .standaloneSetup(apiKeyController)
                .build();

        ApiKey apiKey = new ApiKey(EXISTING_API_KEY_1, "edward", "potts", "potts@mail.com", "appNme", "company");
        apiKey.setKeycloakId(EXISTING_API_KEY_1);
        apiKeyRepo.saveAndFlush(apiKey);

        apiKey = new ApiKey(EXISTING_API_KEY_2, "edward", "bella", "Twilight@mail.com", "appNme", "company");
        apiKey.setKeycloakId(EXISTING_API_KEY_2);
        apiKeyRepo.saveAndFlush(apiKey);

        apiKey = new ApiKey(DEPRECATED_API_KEY, "frank", "sinatra", "sinatra@mail.com", "appName", "company");
        apiKey.setKeycloakId(DEPRECATED_API_KEY);
        apiKey.setDeprecationDate(new Date());
        apiKeyRepo.saveAndFlush(apiKey);

        apiKey = new ApiKey(MIGRATE_API_KEY, "migrate", "migrate", "migrate@mail.com", "migrate", "migrate");
        apiKey.setKeycloakId(MIGRATE_API_KEY);
        apiKey.setDeprecationDate(new Date());
        apiKeyRepo.saveAndFlush(apiKey);

        // api key used for create and update tests
        createApiKeyRequest  = new ApiKeyRequest("Damon", "Salvatore", "damon@gmail.com", "DSApp", "DSCompany");
        captchaApiKeyRequest = new ApiKeyRequest("Stefan", "Salvatore", "stefan@gmail.com", "SSApp", "SSCompany");
        updatedApiKeyRequest = new ApiKeyRequest("Damon", "Salvatore", "damonSalvatore@gmail.com", "AppDS", "DSCompany");
    }

    // CREATE API KEY TESTS
    @Test
    public void testCreateApiKeySuccess() throws Exception {
        prepareForAuthentication(true, false);

        ApiKeySecret createdApiKey = new ApiKeySecret(NEW_API_KEY, createApiKeyRequest.getFirstName(), createApiKeyRequest.getLastName(),
                createApiKeyRequest.getEmail(), createApiKeyRequest.getAppName(), createApiKeyRequest.getCompany(), NEW_CLIENT_SECRET);
        Mockito.when(keycloakManager.createClient(Mockito.any(), Mockito.any())).thenReturn(createdApiKey);

        mvc.perform(post("/apikey").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(createApiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isCreated())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
                .andExpect(MockMvcResultMatchers.content().json(convertApiKeyInJson(createdApiKey)));
    }

    @Test
    public void testCreateApiKeyForbiddenException() throws Exception {
        prepareForAuthentication(false, false);

        mvc.perform(post("/apikey").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(createApiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }

    @Test
    public void testCreateApiKeyMandatoryFieldsMissing() throws Exception {
        prepareForAuthentication(true, false);

        // first name , lastname , email , appname and company missing
        ApiKeyRequest apiKeyRequest = new ApiKeyRequest();
        String expectedErrorMessage = "Required parameter(s): ['firstName', 'lastName', 'email', 'appName', 'company'] not provided";

        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " +(CLIENT_ID + ":" + CLIENT_SECRET))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(apiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
    public void testCreateApiKeyInvalidEmailFormat() throws Exception {
        prepareForAuthentication(true, false);

        // invalid email format
        ApiKeyRequest apiKeyRequest = new ApiKeyRequest("test", "test", "test_gmail**com", "testApp", "test");
        String expectedErrorMessage = "Email is not properly formatted.";

        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(apiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
    public void test_createApiKey_EmailAppNameExist() throws Exception {
        prepareForAuthentication(true, false);

        //existing api key
        ApiKeyRequest apiKeyRequest = new ApiKeyRequest("edward", "potts", "potts@mail.com", "appNme", "company");
        String expectedErrorMessage = "There already is an API key registered with application name "
                + apiKeyRequest.getAppName() + " and email " + apiKeyRequest.getEmail() + ".";

        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(apiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    // CREATE API KEY CAPTCHA TESTS
    @Test
    public void testCreateApiKeyCaptchaMissing() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "Missing Captcha token in the header. Correct syntax: Authorization: Bearer CAPTCHA_TOKEN";

        String actualErrorMessage =  mvc.perform(post("/apikey/captcha").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "dummy " + ACCESS_TOKEN_STRING)
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(captchaApiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andReturn().getResolvedException().getMessage();

       checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
    public void testCreateApiKeyCaptchaVerificationFailed() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "Captcha verification failed.";

        String actualErrorMessage =  mvc.perform(post("/apikey/captcha").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + ACCESS_TOKEN_STRING)
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(captchaApiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
    public void testCreateApiKeyCaptchaForbiddenException() throws Exception {
        prepareForAuthentication(true, false);

        ApiKeyRequest apiKeyRequest = new ApiKeyRequest("test", "test", "test@gmail.com", "testApp", "test");
        Mockito.when(captchaManager.verifyCaptchaToken(Mockito.anyString())).thenReturn(true);

        mvc.perform(post("/apikey/captcha").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + ACCESS_TOKEN_STRING)
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(apiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }

    @Test
    public void testCreateApiKeyCaptchaVerificationSuccess() throws Exception {
        prepareForAuthentication(true, true);

        ApiKeySecret createdApiKey = new ApiKeySecret(CAPTCHA_API_KEY, captchaApiKeyRequest.getFirstName(), captchaApiKeyRequest.getLastName(),
                captchaApiKeyRequest.getEmail(), captchaApiKeyRequest.getAppName(), captchaApiKeyRequest.getCompany(), NEW_CLIENT_SECRET);
        Mockito.when(keycloakManager.createClient(Mockito.any(), Mockito.any())).thenReturn(createdApiKey);

         mvc.perform(post("/apikey/captcha").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + ACCESS_TOKEN_STRING)
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(captchaApiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isCreated())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
               .andExpect(MockMvcResultMatchers.content().json(convertApiKeyInJson(createdApiKey)));
    }

    // API KEY READ TEST
    @Test
    public void testReadApiKey() throws Exception {
        prepareForAuthentication(true, false);

        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(NEW_API_KEY);
        if (optionalExistingApiKey.isEmpty()) {
            fail();
        }
        mvc.perform(get("/apikey/{id}", NEW_API_KEY)
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
                .andExpect(MockMvcResultMatchers.content().json(convertApiKeyInJson(optionalExistingApiKey.get()))); ;
    }

    // UPDATE API KEY TESTS
    @Test
    public void testUpdateApiKeySuccess() throws Exception {
        prepareForAuthentication(true, true);

        mvc.perform(put("/apikey/{id}", NEW_API_KEY).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(updatedApiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)));

        // get the updated api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(NEW_API_KEY);
        if (optionalExistingApiKey.isEmpty()) {
            fail();
        }

        Assert.assertTrue(StringUtils.equals(optionalExistingApiKey.get().getEmail(), updatedApiKeyRequest.getEmail()));
        Assert.assertTrue(StringUtils.equals(optionalExistingApiKey.get().getAppName(), updatedApiKeyRequest.getAppName()));
        Assert.assertTrue(StringUtils.equals(optionalExistingApiKey.get().getCompany(), updatedApiKeyRequest.getCompany()));
    }

    @Test
    public void testUpdateWithNonExistingApiKey() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "API key " + NON_EXISTIG_API_KEY + " does not exist.";

        String actualErrorMessage = mvc.perform(put("/apikey/{id}", NON_EXISTIG_API_KEY).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(updatedApiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNotFound())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
    public void testUpdateWithDeprecatedApiKey() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "The API key " + DEPRECATED_API_KEY + " is deprecated!";

        String actualErrorMessage = mvc.perform(put("/apikey/{id}", DEPRECATED_API_KEY).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(updatedApiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isGone())
                .andReturn().getResolvedException().getMessage();

       checkErrorMessages(actualErrorMessage,expectedErrorMessage);
    }

    // DISABLE CLIENT TESTS
    @Test
    public void testDisableApiKeySuccess() throws Exception {
        prepareForAuthentication(true, false);

        mvc.perform(put("/apikey/{id}/disable", EXISTING_API_KEY_2).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());

        // get the disabled api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(EXISTING_API_KEY_2);
        if (optionalExistingApiKey.isEmpty()) {
            fail();
        }
        // check the deprecated date field
        String currentDate = new SimpleDateFormat("yyyy-MM-dd").format(new Date());

        Assert.assertNotNull(optionalExistingApiKey.get().getDeprecationDate());
        Assert.assertTrue(StringUtils.contains(optionalExistingApiKey.get().getDeprecationDate().toString(), currentDate));
    }

    // ENABLE CLIENT TEST
    @Test
    public void testEnableApiKeyNotDeprecated() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "API key " + EXISTING_API_KEY_1 + " is not deprecated!";

        String actualErrorMessage = mvc.perform(put("/apikey/{id}/enable", EXISTING_API_KEY_1).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " +(CLIENT_ID + ":" + CLIENT_SECRET))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage,expectedErrorMessage);
    }

    @Test
    public void testEnableApiKeySuccess() throws Exception {
        prepareForAuthentication(true, false);

        mvc.perform(put("/apikey/{id}/enable", DEPRECATED_API_KEY).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)));

        // get the enabled api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(DEPRECATED_API_KEY);
        if (optionalExistingApiKey.isEmpty()) {
            fail();
        }
        // check the deprecated date is null
        Assert.assertNull(optionalExistingApiKey.get().getDeprecationDate());
    }

    // DELETE API KEY TESTS
    @Test
    public void testDeleteApiKeySuccess() throws Exception {
        prepareForAuthentication(true, false);

        mvc.perform(delete("/apikey/{id}", EXISTING_API_KEY_2).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());

        // get the deleted api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(EXISTING_API_KEY_2);
        Assert.assertTrue(optionalExistingApiKey.isEmpty());
    }

    @Test
    public void testDeleteApiKeyNotFoundException() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "API key " + NON_EXISTIG_API_KEY + " does not exist.";

        String actualErrorMessage = mvc.perform(delete("/apikey/{id}", NON_EXISTIG_API_KEY).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNotFound())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    // DELETE BY KEYCLOAKID TESTS
    @Test
    public void testDeleteSychroniseApiKeySuccess() throws Exception {
        prepareForAuthentication(true, false);

        mvc.perform(delete("/apikey/synchronize/{keycloakid}", EXISTING_API_KEY_2).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " +(CLIENT_ID + ":" + CLIENT_SECRET))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());

        // get the deleted api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(EXISTING_API_KEY_2);
        Assert.assertTrue(optionalExistingApiKey.isEmpty());
    }

    @Test
    public void testDeleteSychroniseApiKeyNotFound() throws Exception {
        prepareForAuthentication(true, false);

        mvc.perform(delete("/apikey/synchronize/{keycloakid}", NON_EXISTIG_API_KEY).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNotFound());

    }

    // SYNCHRONISE MISSING CLIENT TEST
    @Test
    public void testSychroniseMissingClientSuccess() throws Exception {
        prepareForAuthentication(true, false);

        mvc.perform(post("/apikey/synchronize/missingClient/{apiKey}", MIGRATE_API_KEY).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isCreated());

        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(MIGRATE_API_KEY);
        if (optionalExistingApiKey.isEmpty()) {
            fail();
        }

        // check if keycloakId changed from "to-migrate" to a newly generated one
        Assert.assertTrue(StringUtils.equals(optionalExistingApiKey.get().getKeycloakId(), NEW_KEYCLOACKID));
    }

    @Test
    public void testSychroniseMissingClient_KCIdNotEmptyException() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "ApiKey " + EXISTING_API_KEY_1 + " already has a keycloak client id set (" + EXISTING_API_KEY_1 + ")";

        String actualErrorMessage = mvc.perform(post("/apikey/synchronize/missingClient/{apiKey}", EXISTING_API_KEY_1).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    //SYNCHRONISE ALL TEST
    @Test
    public void testSychroniseALLMissingClient() throws Exception {
        prepareForAuthentication(true, false);
        mvc.perform(post("/apikey/synchronize/missingClient/all", EXISTING_API_KEY_1).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " +(CLIENT_ID + ":" + CLIENT_SECRET))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());
    }

    /**
     * Method to mock Authroization and other Authentication required for Test
     *
     * @param isManagerClientAuthorized to set the isManagerClientAuthorized response
     * @param  prepareForCaptcha if we want the test to be ready for captcha
     */
    private void prepareForAuthentication(boolean isManagerClientAuthorized, boolean prepareForCaptcha) throws ApiKeyException {
        KeycloakPrincipal<KeycloakSecurityContext> principal = Mockito.mock(KeycloakPrincipal.class);
        KeycloakAuthenticationToken token = new KeycloakAuthenticationToken(principal);
        SecurityContextHolder.getContext().setAuthentication(token);
        Mockito.when(keycloakManager.authenticateClient(Mockito.anyString(), Mockito.anyString())).thenReturn(principal);
        Mockito.when(keycloakManager.isManagerClientAuthorized(Mockito.any())).thenReturn(isManagerClientAuthorized);
        Mockito.when(keycloakManager.recreateClient(Mockito.any(), Mockito.anyString(),Mockito.any())).thenReturn(NEW_KEYCLOACKID);
        // prepares mocks for captcha
        if(prepareForCaptcha) {
            Mockito.when(captchaManager.verifyCaptchaToken(Mockito.anyString())).thenReturn(true);
            Mockito.when(customKeycloakAuthenticationProvider.authenticate(Mockito.any(), Mockito.any())).thenReturn(token);
        }
    }

    /**
     * checks the error messages
     *
     * @param actualErrorMessage
     * @param expectedErrorMessage
     */
    private void checkErrorMessages (String actualErrorMessage, String expectedErrorMessage) {
        Assert.assertNotNull(actualErrorMessage);
        Assert.assertTrue(StringUtils.equals(actualErrorMessage, expectedErrorMessage));
    }

    /**
     * Converts the Object to json String
     *
     * @param object object to be converted in jsonString
     * @return json String
     * @throws JsonProcessingException
     */
    private String convertApiKeyInJson(Object object) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.WRAP_ROOT_VALUE, false);
        ObjectWriter ow = mapper.writer().withDefaultPrettyPrinter();
        return ow.writeValueAsString(object);
    }

    @Test
    public void validateExistingApiKey() throws Exception {
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(EXISTING_API_KEY_1);
        if (optionalExistingApiKey.isEmpty()) {
            fail();
        }

        // post validate request
        mvc.perform(post("/apikey/validate").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "APIKEY " + optionalExistingApiKey.get().getApiKey())
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());
    }

    @Test
    public void validateWhenApiKeyNotSupplied() throws Exception {
        // post validate request
        mvc.perform(post("/apikey/validate").secure(true)
                .header(HttpHeaders.AUTHORIZATION, "APIKEY ")
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest());
    }

    @Test
    public void validateUnregisteredApiKey() throws Exception {
        // post validate request
        mvc.perform(post("/apikey/validate").secure(true)
                .header(HttpHeaders.AUTHORIZATION, "APIKEY " + UNREGISTERED_API_KEY)
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    public void validateDeprecatedApiKey() throws Exception {
        Optional<ApiKey> optionalDeprecatedApiKey = apiKeyRepo.findById(DEPRECATED_API_KEY);
        if (optionalDeprecatedApiKey.isEmpty()) {
            fail();
        }

        // post validate request
        mvc.perform(post("/apikey/validate").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "APIKEY " + optionalDeprecatedApiKey.get().getApiKey())
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isGone());
    }
}