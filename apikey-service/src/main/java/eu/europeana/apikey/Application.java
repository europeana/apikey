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
import eu.europeana.apikey.mail.MailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import eu.europeana.apikey.repos.ApiKeyRepo;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
@ComponentScan("eu.europeana.apikey")
public class Application {

    public static void main(String[] args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder();
        builder.sources(Application.class).run(args);
    }

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

@Configuration
@EnableWebMvc
class MailConfig extends WebMvcConfigurerAdapter {
    @Bean
    public SimpleMailMessage apikeyCreatedMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText("Dear %s %s,%n%nThank you for registering for the Europeana API.%n%n" +
                "These are your Europeana API keys: %n%n==========%n" +
                "API key      : %s %nPrivate key  : %s %n==========%n%n" +
                "Please keep a safe record of these keys.%nThe API key is used in all API calls, including the core " +
                "search and record methods. This key does not need to be kept confidential.%n" +
                "The private key is used for specific methods that require additional user authentication. %n" +
                "It must be kept confidential and must not be exposed in user interfaces or in markup%n%n." +
                "Our technical documentation is available at http://labs.europeana.eu/api/ including an API console " +
                "for testing the API, and community developed libraries for a variety of programming languages.%n%n" +
                "Please join us in the Europeana API Forum - https://groups.google.com/forum/?pli=1#!forum/europeanaapi " +
                "- to ask questions to us and other developers and to give us your feedback on our API. " +
                "You can also contact us directly by mailing api@europeana.eu and we'd be especially grateful " +
                "if you would let us know about your implementation so that we can feature it in our application " +
                "gallery on Europeana Labs - http://labs.europeana.eu/apps%n%n" +
                "Best regards,%nThe Europeana API Team%n%nMore about the Europeana API services - " +
                "http://labs.europeana.eu/");
        return message;
    }
}
