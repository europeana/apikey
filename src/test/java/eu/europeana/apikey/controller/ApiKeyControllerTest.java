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
import eu.europeana.apikey.exception.ForbiddenException;
import eu.europeana.apikey.exception.GlobalExceptionHandler;
import eu.europeana.apikey.keycloak.*;
import eu.europeana.apikey.mail.MailService;
import eu.europeana.apikey.repos.ApiKeyRepo;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static net.bytebuddy.matcher.ElementMatchers.is;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

//@FixMethodOrder(MethodSorters.NAME_ASCENDING)
//@RunWith(JUnitPlatform.class)

//@ActiveProfiles("test")
//@RunWith(SpringRunner.class)
//@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = ApiKeyApplication.class)
//@AutoConfigureMockMvc
//@ExtendWith(MockitoExtension.class)
//@TestPropertySource(locations = "classpath:apikey-test.properties")

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = ApiKeyApplication.class)
@AutoConfigureMockMvc
@RunWith(SpringRunner.class)
@TestPropertySource(locations = "classpath:apikey-test.properties")
public class ApiKeyControllerTest {

    private static final String CLIENT_ID = "client";
    private static final String CLIENT_SECRET = "secret";
    private static final String EXISTING_API_KEY = "apikey1";

    @Mock
    private CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;

    @Mock
    private CaptchaManager captchaManager;

    @Autowired
    private ApiKeyRepo apiKeyRepo;

    @Mock
    private KeycloakClientManager keycloakManager;
    private ApiKeyController apiKeyController;
    private MockMvc mvc;
    private SimpleMailMessage apiKeyCreatedMsg;
    private SimpleMailMessage apiKeyAndClientCreatedMsg;
    private SimpleMailMessage clientAddedMsg;
    private MailService emailService;

    private ApiKey successfullyCreatedApikey = TestResources.getSuccessfullyCreatedApiKey();
    private ApiKey existingApikey1 = TestResources.getExistingApiKey1();
    private ApiKey existingApikey2 = TestResources.getExistingApiKey2();
    private ApiKey unregisteredApiKey = TestResources.getUnregisteredApiKey();
    private ApiKey migratedApiKey = TestResources.getMigratedApiKey();
    private ApiKey captchaCreatedApikey = TestResources.getCaptchaCreatedApiKey();
    private ApiKey updatedApikey = TestResources.getUpdatedApiKey();

    private ApiKeyRequest createApiKeyRequest;

//    @Before
//    public void setup() {
//
//        apiKeyController = Mockito.spy(new ApiKeyController(apiKeyRepo,
//                                                            captchaManager,
//                                                            customKeycloakAuthenticationProvider,
//                                                            keycloakClientManager));
//
//        ReflectionTestUtils.setField(apiKeyController, "managerClientId", TestResources.getClientId());
//        ReflectionTestUtils.setField(apiKeyController, "managerClientSecret", TestResources.getClientSecret());
//        ReflectionTestUtils.setField(apiKeyController, "apiKeyCreatedMsg", new SimpleMailMessage());
//
//        mvc = MockMvcBuilders
//                .standaloneSetup(apiKeyController)
//                .build();
//
////        ApiKey apiKey = new ApiKey(TestResources.getExistingApiKey1(), "Edward", "Existing", "edflopps@mail.com", "ThisAppExists", "ExistingFoundation");
////        apiKey.setKeycloakId(TestResources.getExistingApiKey1());
////        apiKeyRepo.saveAndFlush(apiKey);
////
////        apiKey = new ApiKey(TestResources.getExistingApiKey2(), "Elsbeth", "Existingtoo", "twinspizzel@mail.com", "ThisAppExistsToo", "ExistingCompany");
////        apiKey.setKeycloakId(TestResources.getExistingApiKey2());
////        apiKeyRepo.saveAndFlush(apiKey);
////
////        apiKey = new ApiKey(TestResources.getDeprecatedApiKey(), "Dazoozie", "Deprecated", "nononononever@mail.com", "DeprecatedAppAlas", "DeprecatableOrganisation");
////        apiKey.setKeycloakId(TestResources.getDeprecatedApiKey());
////        apiKey.setDeprecationDate(new Date());
////        apiKeyRepo.saveAndFlush(apiKey);
////
////        apiKey = new ApiKey(TestResources.getMigrateApiKey(), "Minko", "Migrator", "migrate@mail.com", "MigratedApp", "MigratableOrganisation");
////        apiKey.setKeycloakId(TestResources.getMigrateApiKey());
////        apiKey.setDeprecationDate(new Date());
//    }


    @Before
    public void setup() {
        emailService = Mockito.mock(MailService.class);
        apiKeyCreatedMsg = Mockito.spy(SimpleMailMessage.class);
        apiKeyAndClientCreatedMsg = Mockito.spy(SimpleMailMessage.class);
        clientAddedMsg = Mockito.spy(SimpleMailMessage.class);

        apiKeyController = Mockito.spy(new ApiKeyController(apiKeyRepo,
                captchaManager,
                customKeycloakAuthenticationProvider,
                keycloakManager));
        ReflectionTestUtils.setField(apiKeyController, "emailService", emailService);
        ReflectionTestUtils.setField(apiKeyController, "managerClientId", CLIENT_ID);
        ReflectionTestUtils.setField(apiKeyController, "managerClientSecret", CLIENT_SECRET);
        ReflectionTestUtils.setField(apiKeyController, "apiKeyCreatedMsg", apiKeyCreatedMsg);
        ReflectionTestUtils.setField(apiKeyController, "apiKeyAndClientCreatedMsg", apiKeyAndClientCreatedMsg);
        ReflectionTestUtils.setField(apiKeyController, "clientAddedMsg", clientAddedMsg);

        mvc = MockMvcBuilders.standaloneSetup(apiKeyController)
                .setControllerAdvice(new GlobalExceptionHandler()).build();

        apiKeyRepo.saveAndFlush(existingApikey1);
        apiKeyRepo.saveAndFlush(existingApikey2);
        apiKeyRepo.saveAndFlush(unregisteredApiKey);
        apiKeyRepo.saveAndFlush(migratedApiKey);

        createApiKeyRequest = new ApiKeyRequest("Damon", "Salvatore", "damon@gmail.com", "DSApp", "DSCompany");
    }

  //  @Test
    public void createApiKeySuccess() throws Exception {
        prepareForAuthentication(true, false);
        Mockito.when(apiKeyController.generatePublicKey()).thenReturn(successfullyCreatedApikey.getApiKey());

        mvc.perform(post("/apikey").secure(true)
                .header(HttpHeaders.AUTHORIZATION, "Basic " + (CLIENT_ID + ":" + CLIENT_SECRET))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(successfullyCreatedApikey)))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isCreated())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
                .andExpect(jsonPath("$.apiKey").value(successfullyCreatedApikey.getApiKey()))
                .andExpect(jsonPath("$.firstName").value(successfullyCreatedApikey.getFirstName()))
                .andExpect(jsonPath("$.lastName").value(successfullyCreatedApikey.getLastName()))
                .andExpect(jsonPath("$.email").value(successfullyCreatedApikey.getEmail()))
                .andExpect(jsonPath("$.appName").value(successfullyCreatedApikey.getAppName()))
                .andExpect(jsonPath("$.company").value(successfullyCreatedApikey.getCompany()))
                .andExpect(jsonPath("$.website").value(successfullyCreatedApikey.getWebsite()))
                .andExpect(jsonPath("$.sector").value(successfullyCreatedApikey.getSector()));
    }


   // @Test
    public void testCreateApiKeyForbiddenException() throws Exception {
        prepareForAuthentication(false, false);
        Mockito.when(apiKeyController.generatePublicKey()).thenReturn(successfullyCreatedApikey.getApiKey());

        String expectedErrorMessage = "Operation is not allowed by this user";

        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(successfullyCreatedApikey)))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isForbidden())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }


  //  @Test
    public void testCreateApiKeyMandatoryFieldsMissing() throws Exception {
        prepareForAuthentication(true, false);

        // first name , lastname , email , appname and company missing
        ApiKeyRequest apiKeyRequest = new ApiKeyRequest();
        String expectedErrorMessage = "Missing parameter. Required parameter(s): ['firstName', 'lastName', 'email', 'appName', 'company'] not provided";

        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(apiKeyRequest)))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

   // @Test
    public void testCreateApiKeyInvalidEmailFormat() throws Exception {
        prepareForAuthentication(true, false);

        // invalid email format
        ApiKeyRequest apiKeyRequest = new ApiKeyRequest("test", "test", "test_gmail**com", "testApp", "test");
        String expectedErrorMessage = "Email is not properly formatted.";

        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(apiKeyRequest)))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

   // @Test
    public void test_createApiKey_EmailAppNameExist() throws Exception {
        prepareForAuthentication(true, false);

        //existing email and app-name api key
        ApiKeyRequest apiKeyRequest = new ApiKeyRequest("test", "existing", TestResources.EXISTINGEMAIL1, TestResources.EXISTINGAPPNAME1, "testCompany");
        String expectedErrorMessage = "There already is an API key registered with application name "
                + apiKeyRequest.getAppName() + " and email " + apiKeyRequest.getEmail() + ".";

        String actualErrorMessage = mvc.perform(post("/apikey").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(apiKeyRequest)))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    // CREATE API KEY CAPTCHA TESTS
   // @Test
    public void testCreateApiKeyCaptchaHeaderMissing() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "Error validating captcha Missing Captcha token in the header. Correct syntax: Authorization: Bearer CAPTCHA_TOKEN";

        String actualErrorMessage =  mvc.perform(post("/apikey/captcha").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "dummy " + TestResources.getAccessTokenString())
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(captchaCreatedApikey)))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andReturn().getResolvedException().getMessage();

       checkErrorMessages(actualErrorMessage, expectedErrorMessage);
    }

    @Test
    public void testCreateApiKeyCaptchaVerificationFailed() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "Error validating captcha Captcha verification failed.";

        String actualErrorMessage =  mvc.perform(post("/apikey/captcha").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + TestResources.getAccessTokenString())
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(captchaCreatedApikey)))
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
                        "Bearer " + TestResources.getAccessTokenString())
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(apiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }

   // @Test
    public void testCreateApiKeyCaptchaVerificationSuccess() throws Exception {
        prepareForAuthentication(true, true);

        Mockito.when(apiKeyController.generatePublicKey()).thenReturn(captchaCreatedApikey.getApiKey());

//        ApiKeySecret createdApiKey = new ApiKeySecret(TestResources.getCaptchaApiKey(), captchaApiKeyRequest.getFirstName(), captchaApiKeyRequest.getLastName(),
//                captchaApiKeyRequest.getEmail(), captchaApiKeyRequest.getAppName(), captchaApiKeyRequest.getCompany(), TestResources.getNewClientSecret());
//        Mockito.when(keycloakClientManager.createClient(Mockito.any(), Mockito.any())).thenReturn(createdApiKey);

         mvc.perform(post("/apikey/captcha").secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + TestResources.getAccessTokenString())
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(captchaCreatedApikey))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isCreated())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
               .andExpect(MockMvcResultMatchers.content().json(convertApiKeyInJson(captchaCreatedApikey)));
    }

    // API KEY READ TEST
   // @Test
    public void testReadApiKey() throws Exception {
        prepareForAuthentication(true, false);

        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(successfullyCreatedApikey.getApiKey());
        if (optionalExistingApiKey.isEmpty()) {
            fail();
        }
        mvc.perform(get("/apikey/{id}", TestResources.getNewApiKey())
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)))
                .andExpect(MockMvcResultMatchers.content().json(convertApiKeyInJson(optionalExistingApiKey.get()))); ;
    }

   /* // UPDATE API KEY TESTS
    @Test
    public void testUpdateApiKeySuccess() throws Exception {
        prepareForAuthentication(true, true);

        mvc.perform(put("/apikey/{id}", TestResources.getNewApiKey()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .contentType(MediaType.APPLICATION_JSON)
                .content(convertApiKeyInJson(updatedApiKeyRequest))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)));

        // get the updated api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(TestResources.getNewApiKey());
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
        String expectedErrorMessage = "API key " + TestResources.getNonExistigApiKey() + " does not exist.";

        String actualErrorMessage = mvc.perform(put("/apikey/{id}", TestResources.getNonExistigApiKey()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
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
        String expectedErrorMessage = "The API key " + TestResources.getDeprecatedApiKey() + " is deprecated!";

        String actualErrorMessage = mvc.perform(put("/apikey/{id}", TestResources.getDeprecatedApiKey()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
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

        mvc.perform(put("/apikey/{id}/disable", TestResources.getExistingApiKey2()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());

        // get the disabled api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(TestResources.getExistingApiKey2());
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
        String expectedErrorMessage = "API key " + TestResources.getExistingApiKey1() + " is not deprecated!";

        String actualErrorMessage = mvc.perform(put("/apikey/{id}/enable", TestResources.getExistingApiKey1()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " +(TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andReturn().getResolvedException().getMessage();

        checkErrorMessages(actualErrorMessage,expectedErrorMessage);
    }

    @Test
    public void testEnableApiKeySuccess() throws Exception {
        prepareForAuthentication(true, false);

        mvc.perform(put("/apikey/{id}/enable", TestResources.getDeprecatedApiKey().secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string("Content-Type", (MediaType.APPLICATION_JSON_VALUE)));

        // get the enabled api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(TestResources.getDeprecatedApiKey());
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

        mvc.perform(delete("/apikey/{id}", TestResources.getExistingApiKey2()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());

        // get the deleted api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(TestResources.getExistingApiKey2());
        Assert.assertTrue(optionalExistingApiKey.isEmpty());
    }

    @Test
    public void testDeleteApiKeyNotFoundException() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "API key " + TestResources.getNonExistigApiKey() + " does not exist.";

        String actualErrorMessage = mvc.perform(delete("/apikey/{id}", TestResources.getNonExistigApiKey()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
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

        mvc.perform(delete("/apikey/synchronize/{keycloakid}", TestResources.getExistingApiKey2()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " +(TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());

        // get the deleted api key
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(TestResources.getExistingApiKey2());
        Assert.assertTrue(optionalExistingApiKey.isEmpty());
    }

    @Test
    public void testDeleteSychroniseApiKeyNotFound() throws Exception {
        prepareForAuthentication(true, false);

        mvc.perform(delete("/apikey/synchronize/{keycloakid}", TestResources.getNonExistigApiKey()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNotFound());

    }

    // SYNCHRONISE MISSING CLIENT TEST
    @Test
    public void testSychroniseMissingClientSuccess() throws Exception {
        prepareForAuthentication(true, false);

        mvc.perform(post("/apikey/synchronize/missingClient/{apiKey}", TestResources.getMigrateApiKey()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isCreated());

        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(TestResources.getMigrateApiKey());
        if (optionalExistingApiKey.isEmpty()) {
            fail();
        }

        // check if keycloakId changed from "to-migrate" to a newly generated one
        Assert.assertTrue(StringUtils.equals(optionalExistingApiKey.get().getKeycloakId(), TestResources.getNewKeycloakid());
    }

    @Test
    public void testSychroniseMissingClient_KCIdNotEmptyException() throws Exception {
        prepareForAuthentication(true, false);
        String expectedErrorMessage = "ApiKey " + TestResources.getExistingApiKey1() + " already has a keycloak client id set (" + TestResources.getExistingApiKey1() + ")";

        String actualErrorMessage = mvc.perform(post("/apikey/synchronize/missingClient/{apiKey}", TestResources.getExistingApiKey1()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " + (TestResources.getClientId() + ":" + TestResources.getClientSecret()))
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
        mvc.perform(post("/apikey/synchronize/missingClient/all", TestResources.getExistingApiKey1()).secure(true)
                .header(HttpHeaders.AUTHORIZATION,
                        "Basic " +(TestResources.getClientId() + ":" + TestResources.getClientSecret()))
                .with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());
    }
*/

    private String convertApiKeyInJson(Object object) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.WRAP_ROOT_VALUE, false);
        ObjectWriter ow = mapper.writer().withDefaultPrettyPrinter();
        return ow.writeValueAsString(object);
    }

    /**
     * Method to mock Authroization and other Authentication required for Test
     *
     * @param isManagerClientAuthorized to set the isManagerClientAuthorized response
     * @param prepareForCaptcha         if we want the test to be ready for captcha
     */
    private void prepareForAuthentication(boolean isManagerClientAuthorized, boolean prepareForCaptcha) throws
            EuropeanaApiException {
        KeycloakPrincipal<KeycloakSecurityContext> principal = Mockito.mock(KeycloakPrincipal.class);
        List<GrantedAuthority> authorities = new ArrayList<>();
        KeycloakAuthenticationToken token = new KeycloakAuthenticationToken(principal, authorities);
        SecurityContextHolder.getContext().setAuthentication(token);
        Mockito.when(keycloakManager.authenticateClient(Mockito.anyString(), Mockito.anyString()))
                .thenReturn(principal);
        Mockito.when(keycloakManager.isManagerClientAuthorized(Mockito.any())).thenReturn(isManagerClientAuthorized);
        // prepares mocks for captcha
        if (prepareForCaptcha) {
            Mockito.when(captchaManager.verifyCaptchaToken(Mockito.anyString())).thenReturn(true);
            Mockito.when(customKeycloakAuthenticationProvider.authenticate(Mockito.any())).thenReturn(token);
        }
    }


//    /**
//     * Method to mock Authrorisation and other Authentication required for Test
//     *
//     * @param isManagerClientAuthorized to set the isManagerClientAuthorized response
//     * @param  prepareForCaptcha if we want the test to be ready for captcha
//     */
//
//    private void prepareForAuthentication(boolean isManagerClientAuthorized, boolean prepareForCaptcha) throws EuropeanaApiException {
//        KeycloakPrincipal           principal = Mockito.mock(KeycloakPrincipal.class);
//        KeycloakAuthenticationToken token     = new KeycloakAuthenticationToken(principal);
//        SecurityContextHolder.getContext().setAuthentication(token);
//
//        Mockito.when(keycloakClientManager.authenticateClient(Mockito.anyString(), Mockito.anyString())).thenReturn(principal);
//        Mockito.when(keycloakClientManager.isManagerClientAuthorized(Mockito.any())).thenReturn(isManagerClientAuthorized);
////        Mockito.when(keycloakClientManager.recreateClient(Mockito.any(), Mockito.anyString(), Mockito.any())).thenReturn(TestResources.getNewKeycloakid());
//        // prepares mocks for captcha
//        if(prepareForCaptcha) {
//            Mockito.when(captchaManager.verifyCaptchaToken(Mockito.anyString())).thenReturn(true);
//            Mockito.when(customKeycloakAuthenticationProvider.authenticateAdminClient(Mockito.any(), Mockito.any())).thenReturn(token);
//        }
//    }


    /**
     * checks the error messages
     *
     * @param actualErrorMessage
     * @param expectedErrorMessage
     */
    private void checkErrorMessages(String actualErrorMessage, String expectedErrorMessage) {
        Assert.assertNotNull(actualErrorMessage);
        assertTrue(StringUtils.equals(actualErrorMessage, expectedErrorMessage));
    }

//    @Test
//    public void validateExistingApiKey() throws Exception {
//        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(TestResources.getExistingApiKey1());
//        if (optionalExistingApiKey.isEmpty()) {
//            fail();
//        }
//
//        // post validate request
//        mvc.perform(post("/apikey/validate").secure(true)
//                                            .header(HttpHeaders.AUTHORIZATION,
//                                                    "APIKEY " + optionalExistingApiKey.get().getApiKey())
//                                            .contentType(MediaType.APPLICATION_JSON)
//                                            .with(csrf()))
//           .andDo(MockMvcResultHandlers.print())
//           .andExpect(MockMvcResultMatchers.status().isNoContent());
//    }

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

//    @Test
//    public void validateUnregisteredApiKey() throws Exception {
//        // post validate request
//        mvc.perform(post("/apikey/validate").secure(true)
//                                            .header(HttpHeaders.AUTHORIZATION,
//                                                    "APIKEY " + TestResources.getUnregisteredApiKey())
//                                            .contentType(MediaType.APPLICATION_JSON)
//                                            .with(csrf()))
//           .andDo(MockMvcResultHandlers.print())
//           .andExpect(MockMvcResultMatchers.status().isUnauthorized());
//    }

    // @Test
    public void validateDeprecatedApiKey() throws Exception {
        Optional<ApiKey> optionalDeprecatedApiKey = apiKeyRepo.findById(TestResources.getDeprecatedApiKey());
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
                .andExpect(status().isGone());
    }

//    @org.junit.jupiter.api.Test
//    void copyValuesToApiKey() {
//    }
//
//    @org.junit.jupiter.api.Test
//    void checkManagerCredentials() {
//    }
//
//    @org.junit.jupiter.api.Test
//    void checkManagerOrOwnerCredentials() {
//    }
//
//    @org.junit.jupiter.api.Test
//    void checkMandatoryFields() {
//    }
//
//    @org.junit.jupiter.api.Test
//    void checkKeyExists() {
//    }
//
//    @org.junit.jupiter.api.Test
//    void checkKeyDeprecated() {
//    }
//
//    @org.junit.jupiter.api.Test
//    void checkKeyEmailAppNameExist() {
//    }


//    @Profile("test")
//    @Configuration
//    public class ApikeyControllerTestSetup {
//
//        @Bean
//        @Primary
//        public MailService emailService(){
//            return Mockito.mock(MailService.class);
//        }
//    }

}