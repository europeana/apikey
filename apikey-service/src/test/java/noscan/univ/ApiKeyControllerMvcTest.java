package noscan.univ;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import univ.repos.ApiKeyRepo;
import univ.util.ClasspathResourceUtils;
import univ.web.ApikeyController;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@WebMvcTest
public class ApiKeyControllerMvcTest {

    @Autowired
    private ApikeyController apiKeyController;

    @Autowired
    private ApiKeyRepo apiKeyRepo;

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testSaveApiKey() throws Exception {
//        String sampleCourseRequest = ClasspathResourceUtils.getResourceContentFromPath("/samples/sampleApiKey.json");
//        this.mockMvc.perform(
//                post("/apikey")
//                        .accept(MediaType.APPLICATION_JSON)
//                        .contentType(MediaType.APPLICATION_JSON)
//                        .content(sampleCourseRequest))
////                .andDo(log())
//                .andExpect(status().isCreated());
//
//        verify(apiKeyRepo, times(1)).findOne("testApiKey");
    }

    @Configuration
    public static class SpringConfig {

        @Bean
        public ApikeyController apiKeyController() {
            return new ApikeyController(apiKeyRepo());
        }

        @Bean
        public ApiKeyRepo apiKeyRepo() {
            ApiKeyRepo mock = mock(ApiKeyRepo.class);
            return mock;
        }
    }
}
