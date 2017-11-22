/*
 * Copyright 2007-2017 The Europeana Foundation
 *
 *  Licenced under the EUPL, Version 1.1 (the "Licence") and subsequent versions as approved
 *  by the European Commission;
 *  You may not use this work except in compliance with the Licence.
 *
 *  You may obtain a copy of the Licence at:
 *  http://joinup.ec.europa.eu/software/page/eupl
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under
 *  the Licence is distributed on an "AS IS" basis, without warranties or conditions of
 *  any kind, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under
 *  the Licence.
 */


/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey;

import eu.europeana.apikey.domain.ApiKey;
import eu.europeana.apikey.repos.ApiKeyRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
@ComponentScan("eu.europeana.apikey")
public class Application {

    public static void main(String[] args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder();
        builder.sources(Application.class).run(args);
    }

//    @Bean
//    public ObjectMapper objectMapper() {
//        return new ObjectMapper()
//                .registerModule(new ProblemModule())
//                .registerModule(new ConstraintViolationProblemModule());
//    }

    @Component
    public static class SampleDataPopulator implements CommandLineRunner {

        @Autowired
        private ApiKeyRepo apiKeyRepo;

        @Override
        public void run(String... args) throws Exception {
        }

//        private ApiKey saveIfNew(ApiKey apikey) {
//            Optional<ApiKey> fromDb = this.courseRepo.findByCourseCode(apikey.getCourseCode());
//
//            if (!fromDb.isPresent()) {
//                return this.courseRepo.save(apikey);
//            }
//            return fromDb.get();
//        }
//        private Teacher sampleTeacher(String name, String department) {
//            return new Teacher(name, department);
//        }

//        private ApiKey sampleCourse(String courseCode, String courseName) {
//            return new ApiKey(courseCode, courseName);
//        }
    }
}
@Configuration
class WebSecurityConfiguration extends GlobalAuthenticationConfigurerAdapter {

    @Autowired
    ApiKeyRepo apiKeyRepo;

    @Override
    public void init(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService());
    }

    @Bean
    UserDetailsService userDetailsService() {
        return new UserDetailsService() {

            @Override
            public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
                ApiKey apikey = apiKeyRepo.findOne(id);
                // && apikey.getLevel().equalsIgnoreCase("ADMIN")
                if(apikey != null) {
                    return new User(apikey.getApiKey(), apikey.getPrivateKey(),
                            true, true, true, true,
                            AuthorityUtils.createAuthorityList(
                                    apikey.getLevel().equalsIgnoreCase("ADMIN") ? "ROLE_ADMIN" : "USER"));
                } else    {
                    throw new UsernameNotFoundException("could not find apikey '"  + id + "'");
                }
            }
        };
    }
}

@EnableWebSecurity
@Configuration
class ApiSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity webSecurity) throws Exception {
        webSecurity
                .ignoring()
                .antMatchers(HttpMethod.GET, "/apikey/**");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http    .authorizeRequests().anyRequest().access("hasRole('ROLE_ADMIN')")
                .and().httpBasic()
                .and().csrf().disable();
    }

}

//@Import(SecurityProblemSupport.class)
//@Configuration
//class SecurityConfiguration extends ResourceServerConfigurerAdapter {
//
//    @Autowired
//    private SecurityProblemSupport problemSupport;
//
//    @Override
//    public void configure(final HttpSecurity http) throws Exception {
//        http.exceptionHandling()
//                .authenticationEntryPoint(problemSupport)
//                .accessDeniedHandler(problemSupport);
//    }
//
//}

@Component
@ConfigurationProperties("europeanamail")
class EuropeanaMailProperties {
    private String register_api_to;
    private String register_api_from;
    private String admin_to;
    private String system_from;
    private String register_to;
    private String feedback_to;
    private String exception_to;
    private String feedback_from;

    public String getRegister_api_to() {
        return register_api_to;
    }
    public void setRegister_api_to(String register_api_to) {
        this.register_api_to = register_api_to;
    }
    public String getRegister_api_from() {
        return register_api_from;
    }
    public void setRegister_api_from(String register_api_from) {
        this.register_api_from = register_api_from;
    }
    public String getAdmin_to() {
        return admin_to;
    }
    public void setAdmin_to(String admin_to) {
        this.admin_to = admin_to;
    }
    public String getSystem_from() {
        return system_from;
    }
    public void setSystem_from(String system_from) {
        this.system_from = system_from;
    }
    public String getRegister_to() {
        return register_to;
    }
    public void setRegister_to(String register_to) {
        this.register_to = register_to;
    }
    public String getFeedback_to() {
        return feedback_to;
    }
    public void setFeedback_to(String feedback_to) {
        this.feedback_to = feedback_to;
    }
    public String getException_to() {
        return exception_to;
    }
    public void setException_to(String exception_to) {
        this.exception_to = exception_to;
    }
    public String getFeedback_from() {
        return feedback_from;
    }
    public void setFeedback_from(String feedback_from) {
            this.feedback_from = feedback_from;
        }

}

@Configuration
@EnableWebMvc
class MailConfig extends WebMvcConfigurerAdapter {
    @Autowired
    private EuropeanaMailProperties europeanaMailProperties;
    @Bean
    public SimpleMailMessage apikeyCreatedMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText("Dear %s %s,%n%nThank you for registering for the Europeana API.%n%n" +
                "These are your Europeana API keys: %n%n==========%n" +
                "API key      : %s %nPrivate key  : %s %n==========%n%n" +
                "Please keep a safe record of these keys.%nThe API key is used in all API calls, including the core " +
                "search and record methods. This key does not need to be kept confidential.%n" +
                "The private key is used for specific methods that require additional user authentication. %n" +
                "It must be kept confidential and must not be exposed in user interfaces or in markup.%n%n" +
                "Our technical documentation is available at http://labs.europeana.eu/api/ including an API console " +
                "for testing the API, and community developed libraries for a variety of programming languages.%n%n" +
                "Please join us in the Europeana API Forum - https://groups.google.com/forum/?pli=1#!forum/europeanaapi " +
                "- to ask questions to us and other developers and to give us your feedback on our API. " +
                "You can also contact us directly by mailing api@europeana.eu and we'd be especially grateful " +
                "if you would let us know about your implementation so that we can feature it in our application " +
                "gallery on Europeana Labs - http://labs.europeana.eu/apps%n%n" +
                "Best regards,%nThe Europeana API Team%n%nMore about the Europeana API services - " +
                "http://labs.europeana.eu/");
        message.setFrom(europeanaMailProperties.getSystem_from());
        return message;
    }
}
