package eu.europeana.apikey;

import eu.europeana.apikey.domain.Apikey;
import eu.europeana.apikey.domain.ApikeyRequest;
import eu.europeana.apikey.repos.ApikeyRepo;
import eu.europeana.apikey.util.ApiName;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
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
import org.springframework.util.Base64Utils;

import java.nio.charset.Charset;
import java.util.Date;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


/**
 * Created by luthien on 20/03/2018.
 */
@RunWith(SpringRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = ApikeyApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-integrationtest.properties")
public class ApikeyFullIntegration {

    private static final String fifisFirstName      = "Fifi";
    private static final String fifisLastName       = "Finufi";
    private static final String fifisEmail          = "fifi@finufi.net";
    private static final String fifisAppName        = "none";
    private static final String fifisCompany        = "Fifi's Bike Repair Shop";
    private static final String fifisSector         = "n/a";
    private static final String fifisWebsite        = "http://fifisbikerepairshop.nl";
    private static final String phypheysFirstName   = "Phyphey";
    private static final String phypheysLastName    = "Phyenoopheye, P. P.";
    private static final String phypheysEmail       = "phyphey@phyenoopheye.org";
    private static final String phypheysAppName     = "Incrowding Assistent";
    private static final String phypheysCompany     = "Smug, Spoiled, Stupid & Arrogant Inc.";
    private static final String phypheysSector      = "The Terminally Hip";
    private static final String phypheysWebsite     = "http://sssa4u.biz";
    private static final ApikeyRequest fifisApikeyCreate = new ApikeyRequest(fifisFirstName, fifisLastName, fifisEmail, fifisAppName, fifisCompany);
    private static final String READ  = "read";


    @Autowired
    private MockMvc mvc;

    @Autowired
    private ApikeyRepo apikeyRepo;

    @Before
    public void setup()throws Exception {
        Apikey adminKey = new Apikey("Apikey1", "luthien",
                                     "inedhil", "luthien@parendili.org", "appName", "company");
        adminKey.setKeycloakId("Apikey1");
        apikeyRepo.saveAndFlush(adminKey);
    }

    // We create an apikey for user Fifi Finufi
    @Ignore
    @Test
    public void aCreateApikey() throws Exception {
        // post one apikeyCreate
        mvc.perform(post("/apikey").header(HttpHeaders.AUTHORIZATION
                , "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes()))
                .contentType(MediaType.APPLICATION_JSON).content(JsonUtil.toJson(fifisApikeyCreate)).with(csrf()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isCreated());

        Optional<Apikey> fifi = apikeyRepo.findByEmail(fifisApikeyCreate.getEmail());

        assertThat(fifi.isPresent()         , equalTo(true));
        assertThat(fifi.get().getFirstName(), equalTo(fifisApikeyCreate.getFirstName()));
        assertThat(fifi.get().getLastName() , equalTo(fifisApikeyCreate.getLastName()));
        assertThat(fifi.get().getEmail()    , equalTo(fifisApikeyCreate.getEmail()));
    }

    // Fifi needs her apikey data updated because she's in management now
    @Ignore
    @Test
    public void bUpdateApikey() throws Exception {
        String fifisApikey = apikeyRepo.findByEmail(fifisEmail).get().getApikey();

        ApikeyRequest phypheysApikeyUpdate = new ApikeyRequest(phypheysFirstName, phypheysLastName
                , phypheysEmail, phypheysAppName, phypheysCompany, phypheysSector, phypheysWebsite);

        mvc.perform(put("/apikey/" + fifisApikey).header(HttpHeaders.AUTHORIZATION
                , "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes()))
                .contentType(MediaType.APPLICATION_JSON).content(JsonUtil.toJson(phypheysApikeyUpdate)).with(csrf()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isOk());

        Optional<Apikey> phyphey = apikeyRepo.findByEmail(phypheysEmail);
        assertThat(phyphey.isPresent()         , equalTo(true));
        assertThat(phyphey.get().getFirstName(), equalTo(phypheysFirstName));
        assertThat(phyphey.get().getLastName() , equalTo(phypheysLastName));
        assertThat(phyphey.get().getEmail()    , equalTo(phypheysEmail));
        assertThat(phyphey.get().getAppName()  , equalTo(phypheysAppName));
        assertThat(phyphey.get().getCompany()  , equalTo(phypheysCompany));
        assertThat(phyphey.get().getSector()   , equalTo(phypheysSector));
        assertThat(phyphey.get().getWebsite()  , equalTo(phypheysWebsite));
    }

    // Phyphey (formerly known as 'Fifi') has her apikey invalidated because of abuse of resources
    @Ignore
    @Test
    public void cInvalidateApikey() throws Exception {
        Apikey phypheysKey = apikeyRepo.findByEmail(phypheysEmail).get();
        String phypheysApikey = phypheysKey.getApikey();

        mvc.perform(delete("/apikey/" + phypheysApikey).header(HttpHeaders.AUTHORIZATION,
                    "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes()))
           .with(csrf()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isNoContent());

        Optional<Apikey> phyphey = apikeyRepo.findByEmail(phypheysEmail);
        assertThat(phyphey.isPresent(), equalTo(true));
        assertNotNull(phyphey.get().getDeprecationDate());

        // let's check if she really can't get it any longer - Deprecation date is set to now by the controller
        mvc.perform(post("/apikey/" + phypheysApikey + "/validate")
                            .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes()))
                            .param("api", ApiName.SEARCH.toString())
                            .param("method", READ)
                            .with(csrf()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isGone());

        // move the deprecation date to next week, she should be able to enter still
        // no need to change it back again, it will be deleted in the next test
        Date nextWeek = new DateTime(DateTimeZone.UTC).plusDays(7).toDate();
        phypheysKey.setDeprecationDate(nextWeek);
        apikeyRepo.saveAndFlush(phypheysKey);
        mvc.perform(post("/apikey/" + phypheysApikey + "/validate")
                            .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes()))
                            .param("api", ApiName.SEARCH.toString())
                            .param("method", READ)
                            .with(csrf()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isNoContent());

    }

    // where Fifi has her apikey re-enabled after she realises the error of her ways, turns her back on "Smug, Stupid,
    // Spoiled & Arrogant Inc." and starts a bike repair shop
    @Ignore
    @Test
    public void dReenableeApikey() throws Exception {
        String phypheysApikey = apikeyRepo.findByEmail(phypheysEmail).get().getApikey();
        ApikeyRequest fifisApikeyUpdate = new ApikeyRequest(fifisFirstName, fifisLastName
                , fifisEmail, fifisAppName, fifisCompany, fifisSector, fifisWebsite);

        mvc.perform(post("/apikey/" + phypheysApikey).header(HttpHeaders.AUTHORIZATION
                , "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes()))
                .contentType(MediaType.APPLICATION_JSON).content(JsonUtil.toJson(fifisApikeyUpdate))
           .with(csrf()))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isOk());

        Optional<Apikey> fifi = apikeyRepo.findByEmail(fifisEmail);

        assertThat(fifi.isPresent()         , equalTo(true));
        assertThat(fifi.get().getFirstName(), equalTo(fifisFirstName));
        assertThat(fifi.get().getLastName() , equalTo(fifisLastName));
        assertThat(fifi.get().getEmail()    , equalTo(fifisEmail));
        assertThat(fifi.get().getAppName()  , equalTo(fifisAppName));
        assertThat(fifi.get().getCompany()  , equalTo(fifisCompany));
        assertThat(fifi.get().getSector()   , equalTo(fifisSector));
        assertThat(fifi.get().getWebsite()  , equalTo(fifisWebsite));
    }

    // where Fifi's details confirm that she is doing great
    // Tests retrieving details for apikey, returning HTTP 200 if successful, HTTP 404 if not found,
    // and a HTTP 406 when requesting a Mimetype we can't provide for
    @Ignore
    @Test
    public void eRetrieveDetails() throws Exception {
        MediaType contentType = new MediaType(MediaType.APPLICATION_JSON.getType(),
                                              MediaType.APPLICATION_JSON.getSubtype(),
                                              Charset.forName("utf8"));
        String fifisApikey = apikeyRepo.findByEmail(fifisEmail).get().getApikey();
        mvc.perform(get("/apikey/" + fifisApikey).header(HttpHeaders.AUTHORIZATION
                , "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes()))
                .with(csrf()))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().contentType(contentType))
                .andExpect(jsonPath("$.firstName", equalTo(fifisFirstName)))
                .andExpect(jsonPath("$.lastName" , equalTo(fifisLastName)))
                .andExpect(jsonPath("$.email"    , equalTo(fifisEmail)))
                .andExpect(jsonPath("$.appName"  , equalTo(fifisAppName)))
                .andExpect(jsonPath("$.company"  , equalTo(fifisCompany)))
                .andExpect(jsonPath("$.sector"   , equalTo(fifisSector)))
                .andExpect(jsonPath("$.website"  , equalTo(fifisWebsite)));

        // test HTTP 404 response for nonexisting key
        mvc.perform(get("/apikey/nezcasse").header(HttpHeaders.AUTHORIZATION
                , "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes())))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isNotFound());

        // test HTTP 406 when wrongfully being requested an unspeakable Mimetype
        mvc.perform(get("/apikey/" + fifisApikey).header(HttpHeaders.AUTHORIZATION
                , "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes()))
                                                 .header(HttpHeaders.ACCEPT, MediaType.IMAGE_JPEG))
           .andExpect(MockMvcResultMatchers.status().isNotAcceptable());
    }

    // where Fifi has her apikey validated, and finds to her delight that she has plenty of resources left
    // Test regular validation call with ample usage left, returning HTTP 204
    @Ignore
    @Test
    public void fValidateApikey() throws Exception {
        String fifisApikey = apikeyRepo.findByEmail(fifisEmail).get().getApikey();
        mvc.perform(post("/apikey/" + fifisApikey + "/validate")
                            .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes()))
                            .with(csrf())
                            .param("api", ApiName.SEARCH.toString())
                            .param("method", READ))
           .andDo(MockMvcResultHandlers.print())
           .andExpect(MockMvcResultMatchers.status().isNoContent());
    }

    // where we'll test our defenses by pretending to forget a required parameter
    // Testing forgetting a parameter, resultint in HTTP 400
    @Ignore
    @Test
    public void geeLetsForgetParameters() throws Exception {
        String fifisApikey = apikeyRepo.findByEmail(fifisEmail).get().getApikey();
        mvc.perform(post("/apikey/" + fifisApikey + "/validate")
                            .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64Utils.encodeToString("Apikey1:PrivateKey1".getBytes()))
                            .with(csrf())
                            .param("method", READ))
           .andExpect(MockMvcResultMatchers.status().isBadRequest());
    }

    // where we'll test the authentication police by trying to enter with forged credits. And one more time.
    // This tests both the HTTP 401 and the 403 responses (nonexisting validation keyset vs unauthorised keyset)
    @Ignore
    @Test
    public void heySneakingPastSecurity() throws Exception {
        String fifisApikey = apikeyRepo.findByEmail(fifisEmail).get().getApikey();
        mvc.perform(post("/apikey/" + fifisApikey + "/validate")
                            .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64Utils.encodeToString("SnorPipo5Soep:Blauwbek7".getBytes()))
                            .with(csrf())
                            .param("api", ApiName.SEARCH.toString())
                            .param("method", READ))
           .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Ignore
    @Test
    public void zhouldReturnDefaultMessage() throws Exception {
        this.mvc.perform(get("/apikey")).andDo(print()).andExpect(status().isOk())
                    .andExpect(content().string(containsString("Hello World!")));
    }

}
