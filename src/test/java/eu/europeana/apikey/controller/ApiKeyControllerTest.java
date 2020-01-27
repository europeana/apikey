package eu.europeana.apikey.controller;

import eu.europeana.apikey.ApiKeyApplication;
import eu.europeana.apikey.domain.ApiKey;
import eu.europeana.apikey.repos.ApiKeyRepo;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.util.Date;
import java.util.Optional;

import static org.junit.Assert.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@RunWith(SpringRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = ApiKeyApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:apikey-test.properties")
public class ApiKeyControllerTest {

    private static final String EXISTING_API_KEY        = "apikey1";
    private static final String UNREGISTERED_API_KEY    = "apikey2";
    private static final String DEPRECATED_API_KEY      = "apikey3";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ApiKeyRepo apiKeyRepo;

    @Before
    public void setup() {
        ApiKey apiKey = new ApiKey(EXISTING_API_KEY, "edward", "potts", "potts@mail.com", "appNme", "company");
        apiKey.setKeycloakId(EXISTING_API_KEY);
        apiKeyRepo.saveAndFlush(apiKey);

        apiKey = new ApiKey(DEPRECATED_API_KEY, "frank", "sinatra", "sinatra@mail.com", "appName", "company");
        apiKey.setKeycloakId(DEPRECATED_API_KEY);
        apiKey.setDeprecationDate(new Date());
        apiKeyRepo.saveAndFlush(apiKey);
    }

    @Test
    public void validateExistingApiKey() throws Exception {
        Optional<ApiKey> optionalExistingApiKey = apiKeyRepo.findById(EXISTING_API_KEY);
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