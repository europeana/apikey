package eu.europeana.apikey.controller;

import eu.europeana.apikey.ApiKeyApplication;
import eu.europeana.apikey.domain.Apikey;
import eu.europeana.apikey.repos.ApikeyRepo;
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

import static org.junit.Assert.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@RunWith(SpringRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = ApiKeyApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-integrationtest.properties")
public class ApikeyControllerTest {

    private static final String EXISTING_API_KEY = "apikey1";

    private static final String UNREGISTERED_API_KEY = "apikey2";

    private static final String DEPRECATED_API_KEY = "apikey3";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ApikeyRepo apikeyRepo;

    @Before
    public void setup()throws Exception {
        Apikey apikey = new Apikey(EXISTING_API_KEY, "edward",
                "potts", "potts@mail.com","appNme", "company");
        apikey.setKeycloakId(EXISTING_API_KEY);
        apikeyRepo.saveAndFlush(apikey);

        apikey = new Apikey(DEPRECATED_API_KEY, "frank",
                "sinatra", "sinatra@mail.com","appName", "company");
        apikey.setKeycloakId(DEPRECATED_API_KEY);
        apikey.setDeprecationDate(new Date());
        apikeyRepo.saveAndFlush(apikey);
    }

    @Test
    public void validateExistingApikey() throws Exception {
        Apikey existing = apikeyRepo.findOne(EXISTING_API_KEY);

        if (existing == null) {
            fail();
        }

        // post validate request
        mvc.perform(post("/apikey/validate").header(HttpHeaders.AUTHORIZATION
                , "APIKEY " + existing.getApikey())
                .contentType(MediaType.APPLICATION_JSON).with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isNoContent());
    }

    @Test
    public void validateWhenApikeyNotSupplied() throws Exception {
        // post validate request
        mvc.perform(post("/apikey/validate").header(HttpHeaders.AUTHORIZATION
                , "APIKEY ")
                .contentType(MediaType.APPLICATION_JSON).with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isBadRequest());
    }

    @Test
    public void validateUnregisteredApikey() throws Exception {
        // post validate request
        mvc.perform(post("/apikey/validate").header(HttpHeaders.AUTHORIZATION
                , "APIKEY " + UNREGISTERED_API_KEY)
                .contentType(MediaType.APPLICATION_JSON).with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    public void validateDeprecatedApikey() throws Exception {
        Apikey deprecated = apikeyRepo.findOne(DEPRECATED_API_KEY);

        if (deprecated == null) {
            fail();
        }

        // post validate request
        mvc.perform(post("/apikey/validate").header(HttpHeaders.AUTHORIZATION
                , "APIKEY " + deprecated.getApikey())
                .contentType(MediaType.APPLICATION_JSON).with(csrf()))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isGone());
    }
}