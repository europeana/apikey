package eu.europeana.apikey.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.europeana.api.commons.error.EuropeanaApiException;
import eu.europeana.apikey.ApiKeyApplication;
import eu.europeana.apikey.TestResources;
import eu.europeana.apikey.captcha.CaptchaManager;
import eu.europeana.apikey.domain.ApiKey;
import eu.europeana.apikey.domain.ApiKeyRequest;
import eu.europeana.apikey.exception.GlobalExceptionHandler;
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
import org.keycloak.representations.idm.ClientRepresentation;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = ApiKeyApplication.class)
@AutoConfigureMockMvc
@RunWith(SpringRunner.class)
@TestPropertySource(locations = "classpath:apikey-test.properties")
public class ApiKeyControllerTest {

    private static final String CLIENT_ID     = "client";
    private static final String CLIENT_SECRET = "secret";

    private ApiKeyController  apiKeyController;
    private MockMvc           mvc;

    @Mock
    private CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;
    @Mock
    private CaptchaManager                       captchaManager;
    @Autowired
    private ApiKeyRepo                           apiKeyRepo;
    @Mock
    private KeycloakClientManager                keycloakManager;

    @Before
    public void setup() {
        MailService       emailService              = mock(MailService.class);
        SimpleMailMessage apiKeyCreatedMsg = Mockito.spy(SimpleMailMessage.class);
        SimpleMailMessage apiKeyAndClientCreatedMsg = Mockito.spy(SimpleMailMessage.class);
        SimpleMailMessage clientAddedMsg = Mockito.spy(SimpleMailMessage.class);

        apiKeyController = Mockito.spy(new ApiKeyController(apiKeyRepo,
                                                            captchaManager,
                                                            customKeycloakAuthenticationProvider,
                                                            keycloakManager));
        ReflectionTestUtils.setField(apiKeyController, "emailService", emailService);
        ReflectionTestUtils.setField(apiKeyController, "apiKeyCreatedMsg", apiKeyCreatedMsg);
        ReflectionTestUtils.setField(apiKeyController, "apiKeyAndClientCreatedMsg", apiKeyAndClientCreatedMsg);
        ReflectionTestUtils.setField(apiKeyController, "clientAddedMsg", clientAddedMsg);

        mvc = MockMvcBuilders.standaloneSetup(apiKeyController)
                             .setControllerAdvice(new GlobalExceptionHandler())
                             .build();

        apiKeyRepo.saveAndFlush(TestResources.getExistingApiKey1());
        apiKeyRepo.saveAndFlush(TestResources.getExistingApiKey2());
        apiKeyRepo.saveAndFlush(TestResources.getUnregisteredApiKey());
        apiKeyRepo.saveAndFlush(TestResources.getMigratedApiKey());
    }

    @Test
        public void createApiKeySuccess() throws Exception {
        prepareForAuthentication(true, false);
        when(apiKeyController.generatePublicKey()).thenReturn(TestResources.getSuccessfullyCreatedApiKey().getApiKey());

        mvc.perform(post("/apikey").secure(true)
                                   .header(HttpHeaders.AUTHORIZATION, "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                                   .contentType(MediaType.APPLICATION_JSON)
                                   .content(convertApiKeyInJson(TestResources.getSuccessfulApiKeyRequest())))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(status().isCreated())
           .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
           .andExpect(jsonPath("$.apiKey").value(TestResources.getSuccessfullyCreatedApiKey().getApiKey()))
           .andExpect(jsonPath("$.firstName").value(TestResources.getSuccessfullyCreatedApiKey().getFirstName()))
           .andExpect(jsonPath("$.lastName").value(TestResources.getSuccessfullyCreatedApiKey().getLastName()))
           .andExpect(jsonPath("$.email").value(TestResources.getSuccessfullyCreatedApiKey().getEmail()))
           .andExpect(jsonPath("$.appName").value(TestResources.getSuccessfullyCreatedApiKey().getAppName()))
           .andExpect(jsonPath("$.company").value(TestResources.getSuccessfullyCreatedApiKey().getCompany()))
           .andExpect(jsonPath("$.website").value(TestResources.getSuccessfullyCreatedApiKey().getWebsite()))
           .andExpect(jsonPath("$.sector").value(TestResources.getSuccessfullyCreatedApiKey().getSector()));
    }

    @Test
        public void testCreateApiKeyForbiddenException() throws Exception {
        // set auth up to fail
        prepareForAuthentication(false, false);
        when(apiKeyController.generatePublicKey()).thenReturn(TestResources.getSuccessfullyCreatedApiKey().getApiKey());
        String expectedErrorMessage = "Operation is not allowed by this user";

        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                                                               .header(HttpHeaders.AUTHORIZATION,
                                                                       TestResources.getBasicauth())
                                                               .contentType(MediaType.APPLICATION_JSON)
                                                               .content(convertApiKeyInJson(TestResources.getSuccessfulApiKeyRequest())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isForbidden())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
        public void testCreateApiKeyMandatoryFieldsMissing() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage
                = "Missing parameter. Required parameter(s): ['firstName', 'lastName', 'email', 'appName', 'company'] not provided";
        // supplying empty ApiKeyRequest
        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                                                               .header(HttpHeaders.AUTHORIZATION,
                                                                       TestResources.getBasicauth())
                                                               .contentType(MediaType.APPLICATION_JSON)
                                                               .content(convertApiKeyInJson(new ApiKeyRequest())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isBadRequest())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
        public void testCreateApiKeyInvalidEmailFormat() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "Email this.fails**com is not properly formatted.";

        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                                                               .header(HttpHeaders.AUTHORIZATION,
                                                                       TestResources.getBasicauth())
                                                               .contentType(MediaType.APPLICATION_JSON)
                                                               .content(convertApiKeyInJson(TestResources.getFailMailRequest())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isBadRequest())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
        public void testCreateApiKeyEmailAppNameExist() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "There already is an API key registered with application name "
                                      + TestResources.getExistingApiKeyRequest1().getAppName()
                                      + " and email "
                                      + TestResources.getExistingApiKeyRequest1().getEmail()
                                      + ".";
        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                                                               .header(HttpHeaders.AUTHORIZATION,
                                                                       TestResources.getBasicauth())
                                                               .contentType(MediaType.APPLICATION_JSON)
                                                               .content(convertApiKeyInJson(TestResources.getExistingApiKeyRequest1())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isBadRequest())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    // CREATE API KEY CAPTCHA TESTS
    @Test
        public void testCreateApiKeyCaptchaVerificationSuccess() throws Exception {
        prepareForAuthentication(false, true);
        when(apiKeyController.generatePublicKey()).thenReturn(TestResources.getCaptchaCreatedApiKey().getApiKey());

        mvc.perform(post("/apikey/captcha").secure(true)
                                           .header(HttpHeaders.AUTHORIZATION, TestResources.getCaptchaToken())
                                           .contentType(MediaType.APPLICATION_JSON)
                                           .content(convertApiKeyInJson(TestResources.getCaptchaApiKeyRequest())))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(status().isCreated())
           .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
           .andExpect(jsonPath("$.apiKey").value(TestResources.getCaptchaCreatedApiKey().getApiKey()))
           .andExpect(jsonPath("$.firstName").value(TestResources.getCaptchaCreatedApiKey().getFirstName()))
           .andExpect(jsonPath("$.lastName").value(TestResources.getCaptchaCreatedApiKey().getLastName()))
           .andExpect(jsonPath("$.email").value(TestResources.getCaptchaCreatedApiKey().getEmail()))
           .andExpect(jsonPath("$.appName").value(TestResources.getCaptchaCreatedApiKey().getAppName()))
           .andExpect(jsonPath("$.company").value(TestResources.getCaptchaCreatedApiKey().getCompany()));
    }

    @Test
        public void testCreateApiKeyWrongCaptchaHeader() throws Exception {
        prepareForAuthentication(false, true);
        String expectedErrorMessage
                = "Error validating captcha Missing or malformed Captcha token. Correct syntax header is: Authorization: Bearer CAPTCHA_TOKEN";
        String actualErrorMessage = mvc.perform(post("/apikey/captcha").secure(true)
                                                                       .header(HttpHeaders.AUTHORIZATION,
                                                                               TestResources.getWrongCaptchaToken())
                                                                       .contentType(MediaType.APPLICATION_JSON)
                                                                       .content(convertApiKeyInJson(TestResources.getCaptchaApiKeyRequest2())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
        public void testCreateApiKeyCaptchaVerificationFailed() throws Exception {
        // prepare authentication to fail
        prepareForAuthentication(false, false);
        String expectedErrorMessage = "Error validating captcha Captcha verification failed.";
        String actualErrorMessage = mvc.perform(post("/apikey/captcha").secure(true)
                                                                       .header(HttpHeaders.AUTHORIZATION,
                                                                               TestResources.getCaptchaToken())
                                                                       .contentType(MediaType.APPLICATION_JSON)
                                                                       .content(convertApiKeyInJson(TestResources.getCaptchaApiKeyRequest())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
        public void testCreateApiKeyCaptchaUnauthorizedException() throws Exception {
        // prepare authentication to fail
        prepareForAuthentication(false, false);
        mvc.perform(post("/apikey/captcha").secure(true)
                                           .header(HttpHeaders.AUTHORIZATION, TestResources.getCaptchaToken())
                                           .contentType(MediaType.APPLICATION_JSON)
                                           .content(convertApiKeyInJson(TestResources.getCaptchaApiKeyRequest2()))
                                           .with(csrf()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    // API KEY READ TEST
    @Test
        public void testReadApiKey() throws Exception {
        prepareForAuthentication(true, false);

        ApiKey           actuallyExistingApikey1    = null;
        Optional<ApiKey> potentiallyExistingApiKey1 = apiKeyRepo.findById(TestResources.getExistingApiKey1().getApiKey());
        if (potentiallyExistingApiKey1.isEmpty()) {
            fail();
        } else {
            actuallyExistingApikey1 = potentiallyExistingApiKey1.get();
        }
        mvc.perform(get("/apikey/{id}", TestResources.getExistingApiKey1().getApiKey()).secure(true)
                                                                    .header(HttpHeaders.AUTHORIZATION,
                                                                            TestResources.getBasicauth()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isOk())
           .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
           .andExpect(jsonPath("$.apiKey").value(actuallyExistingApikey1.getApiKey()))
           .andExpect(jsonPath("$.firstName").value(actuallyExistingApikey1.getFirstName()))
           .andExpect(jsonPath("$.lastName").value(actuallyExistingApikey1.getLastName()))
           .andExpect(jsonPath("$.email").value(actuallyExistingApikey1.getEmail()))
           .andExpect(jsonPath("$.appName").value(actuallyExistingApikey1.getAppName()))
           .andExpect(jsonPath("$.company").value(actuallyExistingApikey1.getCompany()));
    }

    // UPDATE API KEY TESTS
    @Test
        public void testUpdateApiKeySuccess() throws Exception {
        prepareForAuthentication(true, false);

        ApiKey actuallyUpdatedApikey1 = null;
        mvc.perform(put("/apikey/{id}", TestResources.getExistingApiKey1().getApiKey()).secure(true)
                                                        .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                                                        .contentType(MediaType.APPLICATION_JSON)
                                                        .content(convertApiKeyInJson(TestResources.getUpdateApiKeyRequest1())))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isOk())
           .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)));

        // get the updated api key
        Optional<ApiKey> potentiallyUpdatedApiKey = apiKeyRepo.findById(TestResources.getExistingApiKey1().getApiKey());
        if (potentiallyUpdatedApiKey.isEmpty()) {
            fail();
        } else {
            actuallyUpdatedApikey1 = potentiallyUpdatedApiKey.get();
        }

        Assert.assertTrue(StringUtils.equals(actuallyUpdatedApikey1.getFirstName(),
                                             TestResources.getUpdateApiKeyRequest1().getFirstName()));
        Assert.assertTrue(StringUtils.equals(actuallyUpdatedApikey1.getLastName(), TestResources.getUpdateApiKeyRequest1().getLastName()));
        Assert.assertTrue(StringUtils.equals(actuallyUpdatedApikey1.getEmail(), TestResources.getUpdateApiKeyRequest1().getEmail()));
        Assert.assertTrue(StringUtils.equals(actuallyUpdatedApikey1.getAppName(), TestResources.getUpdateApiKeyRequest1().getAppName()));
        Assert.assertTrue(StringUtils.equals(actuallyUpdatedApikey1.getCompany(), TestResources.getUpdateApiKeyRequest1().getCompany()));
    }

    @Test
        public void testUpdateWithNonExistingApiKey() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "API key " + TestResources.getNonexistingkey() + " does not exist.";

        String actualErrorMessage = mvc.perform(put("/apikey/{id}", TestResources.getNonexistingkey())
                                                        .secure(true)
                                                        .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                                                        .contentType(MediaType.APPLICATION_JSON)
                                                        .content(convertApiKeyInJson(TestResources.getUpdateApiKeyRequest1())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isNotFound())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
        public void testUpdateApiKeyWithMissingFields() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "Missing parameter. Required parameter(s): ['%s'] not provided";
        String actualErrorMessage = mvc.perform(put("/apikey/{id}", TestResources.getExistingApiKey1().getApiKey())
                                                        .secure(true)
                                                        .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                                                        .contentType(MediaType.APPLICATION_JSON)
                                                        .content(convertApiKeyInJson(TestResources.getMissingFirstNameUpdateRequest1())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isBadRequest())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, "firstName", expectedErrorMessage);

        actualErrorMessage = mvc.perform(put("/apikey/{id}", TestResources.getExistingApiKey1().getApiKey())
                                                        .secure(true)
                                                        .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                                                        .contentType(MediaType.APPLICATION_JSON)
                                                        .content(convertApiKeyInJson(TestResources.getMissingLastNameUpdateRequest1())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isBadRequest())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, "lastName", expectedErrorMessage);

        actualErrorMessage = mvc.perform(put("/apikey/{id}", TestResources.getExistingApiKey1().getApiKey())
                                                        .secure(true)
                                                        .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                                                        .contentType(MediaType.APPLICATION_JSON)
                                                        .content(convertApiKeyInJson(TestResources.getMissingEmailUpdateRequest1())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isBadRequest())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, "email", expectedErrorMessage);

        actualErrorMessage = mvc.perform(put("/apikey/{id}", TestResources.getExistingApiKey1().getApiKey())
                                                        .secure(true)
                                                        .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                                                        .contentType(MediaType.APPLICATION_JSON)
                                                        .content(convertApiKeyInJson(TestResources.getMissingAppNameUpdateRequest1())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isBadRequest())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, "appName", expectedErrorMessage);

        actualErrorMessage = mvc.perform(put("/apikey/{id}", TestResources.getExistingApiKey1().getApiKey())
                                                 .secure(true)
                                                 .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                                                 .contentType(MediaType.APPLICATION_JSON)
                                                 .content(convertApiKeyInJson(TestResources.getMissingCompanyUpdateRequest1())))
                                .andDo(MockMvcResultHandlers.print())
                                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                                .andReturn()
                                .getResolvedException()
                                .getMessage();
        checkErrorMessages(actualErrorMessage, "company", expectedErrorMessage);
    }

    @Test
        public void testDisableEnableApiKey() throws Exception {
        prepareForAuthentication(true, false);
        mvc.perform(put("/apikey/{id}/disable", TestResources.getExistingApiKey1().getApiKey())
                            .secure(true)
                            .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isNoContent());

        mvc.perform(put("/apikey/{id}/enable", TestResources.getExistingApiKey1().getApiKey())
                            .secure(true)
                            .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isOk())
           .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
           .andExpect(jsonPath("$.apiKey").value(TestResources.getExistingApiKey1().getApiKey()))
           .andExpect(jsonPath("$.firstName").value(TestResources.getExistingApiKey1().getFirstName()))
           .andExpect(jsonPath("$.lastName").value(TestResources.getExistingApiKey1().getLastName()))
           .andExpect(jsonPath("$.email").value(TestResources.getExistingApiKey1().getEmail()))
           .andExpect(jsonPath("$.appName").value(TestResources.getExistingApiKey1().getAppName()))
           .andExpect(jsonPath("$.company").value(TestResources.getExistingApiKey1().getCompany()));
    }

    @Test
        public void testUpdateWithDeprecatedApiKey() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "The API key " + TestResources.getExistingApiKey1().getApiKey() + " is deprecated!";

        mvc.perform(put("/apikey/{id}/disable", TestResources.getExistingApiKey1().getApiKey())
                            .secure(true)
                            .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isNoContent());

        String actualErrorMessage = mvc.perform(put("/apikey/{id}", TestResources.getExistingApiKey1().getApiKey())
                                                        .secure(true)
                                                        .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                                                        .contentType(MediaType.APPLICATION_JSON)
                                                        .content(convertApiKeyInJson(TestResources.getUpdateApiKeyRequest1())))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isGone())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    // DELETE API KEY TESTS
    @Test
    public void testDeleteApiKey() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "API key " + TestResources.getExistingApiKey2().getApiKey() + " does not exist.";
        mvc.perform(delete("/apikey/{id}", TestResources.getExistingApiKey2().getApiKey())
                            .secure(true)
                            .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());

        // get the deleted api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById( TestResources.getExistingApiKey2().getApiKey());
        Assert.assertTrue(optionalExistingApiKey.isEmpty());

        String actualErrorMessage = mvc.perform(delete("/apikey/{id}", TestResources.getExistingApiKey2().getApiKey())
                                                        .secure(true)
                                                        .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth()))
                                       .andDo(MockMvcResultHandlers.print())
                                       .andExpect(MockMvcResultMatchers.status().isNotFound())
                                       .andReturn()
                                       .getResolvedException()
                                       .getMessage();
        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    // keycloak Test
    @Test
    public void testCreateKeyAndClientMissingDataException() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "Missing parameter. Required parameter(s): ['firstName', 'lastName', 'email', 'appName', 'company'] not provided";
        String actualErrorMessage = mvc.perform(post("/apikey/keycloak")
                .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(new ApiKeyRequest())))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isBadRequest())
                .andReturn()
                .getResolvedException()
                .getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
    public void testCreateKeyAndClientApiKeyExistException() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "There already is an API key registered with application name "
                + TestResources.getExistingApiKeyRequest1().getAppName()
                + " and email "
                + TestResources.getExistingApiKeyRequest1().getEmail()
                + ".";
        String actualErrorMessage = mvc.perform(post("/apikey/keycloak")
                .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(TestResources.getExistingApiKey1())))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isBadRequest())
                .andReturn()
                .getResolvedException()
                .getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
    public void testCreateKeyAndClientSuccess() throws Exception {
        prepareForAuthentication(true, false);

        when(apiKeyController.generatePublicKey()).thenReturn(TestResources.getSuccessfulKeycloakApiKeyRequest().getApiKey());
        ClientRepresentation clientRepresentation = Mockito.spy(ClientRepresentation.class);
        when(keycloakManager.createClient(Mockito.any(), Mockito.any())).thenReturn(clientRepresentation);
        when(clientRepresentation.getId()).thenReturn("testKeycloakID");

        mvc.perform(post("/apikey/keycloak").secure(true)
                .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(TestResources.getSuccessfulKeycloakApiKeyRequest())))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isCreated())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
                .andExpect(jsonPath("$.apiKey").value(TestResources.getSuccessfulKeycloakApiKeyRequest().getApiKey()))
                .andExpect(jsonPath("$.firstName").value(TestResources.getSuccessfulKeycloakApiKeyRequest().getFirstName()))
                .andExpect(jsonPath("$.lastName").value(TestResources.getSuccessfulKeycloakApiKeyRequest().getLastName()))
                .andExpect(jsonPath("$.email").value(TestResources.getSuccessfulKeycloakApiKeyRequest().getEmail()))
                .andExpect(jsonPath("$.appName").value(TestResources.getSuccessfulKeycloakApiKeyRequest().getAppName()))
                .andExpect(jsonPath("$.company").value(TestResources.getSuccessfulKeycloakApiKeyRequest().getCompany()))
                .andExpect(jsonPath("$.website").value(TestResources.getSuccessfulKeycloakApiKeyRequest().getWebsite()))
                .andExpect(jsonPath("$.sector").value(TestResources.getSuccessfulKeycloakApiKeyRequest().getSector()));
    }

    @Test
    public void testKeycloakAddClientKCIDNotEmptyException() throws Exception {
        prepareForAuthentication(true, false);

        ApiKey           actuallyExistingApikey1    = null;
        Optional<ApiKey> potentiallyExistingApiKey1 = apiKeyRepo.findById(TestResources.getExistingApiKey1().getApiKey());
        if (potentiallyExistingApiKey1.isEmpty()) {
            fail();
        } else {
            actuallyExistingApikey1 = potentiallyExistingApiKey1.get();
        }

        String expectedErrorMessage = "ApiKey " + actuallyExistingApikey1.getApiKey() +
                " already has a keycloak client id set ("+actuallyExistingApikey1.getKeycloakId() + ")";

        String actualErrorMessage = mvc.perform(post("/apikey/keycloak/{apiKey}", actuallyExistingApikey1.getApiKey())
                .secure(true)
                .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                .contentType(MediaType.APPLICATION_JSON))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isBadRequest()).andReturn()
                .getResolvedException()
                .getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
    public void testKeycloakAddClientSuccess() throws Exception {
        prepareForAuthentication(true, false);

        ClientRepresentation clientRepresentation = Mockito.spy(ClientRepresentation.class);
        when(keycloakManager.createClient(Mockito.any(), Mockito.any())).thenReturn(clientRepresentation);
        when(clientRepresentation.getId()).thenReturn(TestResources.EXISTING2KeycloakID);

        ApiKey           actuallyExistingApikey1    = null;
        Optional<ApiKey> potentiallyExistingApiKey1 = apiKeyRepo.findById(TestResources.getExistingApiKey2().getApiKey());
        if (potentiallyExistingApiKey1.isEmpty()) {
            fail();
        } else {
            actuallyExistingApikey1 = potentiallyExistingApiKey1.get();
        }

        mvc.perform(post("/apikey/keycloak/{apiKey}", actuallyExistingApikey1.getApiKey())
                .secure(true)
                .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                .contentType(MediaType.APPLICATION_JSON))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isCreated());
    }


    @Test
    public void testValidateApikey() throws Exception {
        prepareForAuthentication(true, false);

        String expectedErrorMessage = "No API key in header. Correct header syntax 'Authorization: APIKEY <your_key_here>'";

        String actualErrorMessage = mvc.perform(post("/apikey/validate")
                .secure(true)
                .header(HttpHeaders.AUTHORIZATION, TestResources.getBasicauth())
                .contentType(MediaType.APPLICATION_JSON))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isBadRequest()).andReturn()
                .getResolvedException()
                .getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }


    private String convertApiKeyInJson(Object object) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.WRAP_ROOT_VALUE, false);
        ObjectWriter ow = mapper.writer().withDefaultPrettyPrinter();
        return ow.writeValueAsString(object);
    }

    /**
     * Method to mock Authorization and other Authentication required for Test
     *
     * @param isManagerClientAuthorized to set the isManagerClientAuthorized response
     * @param prepareForCaptcha         if we want the test to be ready for captcha
     */
    private void prepareForAuthentication(boolean isManagerClientAuthorized, boolean prepareForCaptcha) throws
                                                                                                        EuropeanaApiException {
        KeycloakPrincipal<KeycloakSecurityContext> principal   = mock(KeycloakPrincipal.class);
        List<GrantedAuthority>                     authorities = new ArrayList<>();
        KeycloakAuthenticationToken                token       = new KeycloakAuthenticationToken(principal,
                                                                                                 authorities);
        SecurityContextHolder.getContext().setAuthentication(token);
        when(keycloakManager.authenticateClient(Mockito.anyString(), Mockito.anyString())).thenReturn(principal);
        when(keycloakManager.isManagerClientAuthorized(Mockito.any())).thenReturn(isManagerClientAuthorized);
        // prepares mocks for captcha
        if (prepareForCaptcha) {
            when(captchaManager.verifyCaptchaToken(Mockito.anyString())).thenReturn(true);
            when(customKeycloakAuthenticationProvider.authenticateAdminClient(Mockito.any(), Mockito.any())).thenReturn(
                    token);
        }
    }


    /**
     * checks the error messages using %s formatting
     *
     * @param placeholderErrorMessage error message containing %s placeholder to compare
     * @param parameter the string to use in the %s placeholder in the parametrisedErrorMessage
     * @param expectedErrorMessage the string to compare it with
     */
    private void checkErrorMessages(String placeholderErrorMessage, String parameter, String expectedErrorMessage) {
        checkErrorMessages(placeholderErrorMessage, (String.format(expectedErrorMessage, parameter)));
    }

    /**
     * checks the error messages
     *
     * @param actualErrorMessage error message to compare
     * @param expectedErrorMessage the string to compare it with
     */
    private void checkErrorMessages(String actualErrorMessage, String expectedErrorMessage) {
        Assert.assertNotNull(actualErrorMessage);
        assertTrue(StringUtils.equals(actualErrorMessage, expectedErrorMessage));
    }

    // @Test
    public void validateWhenApiKeyNotSupplied() throws Exception {
        // post validate request
        mvc.perform(post("/apikey/validate").secure(true)
                                            .header(HttpHeaders.AUTHORIZATION, "APIKEY ")
                                            .contentType(MediaType.APPLICATION_JSON)
                                            .with(csrf()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(status().isBadRequest());
    }


}