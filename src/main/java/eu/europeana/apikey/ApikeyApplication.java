/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.PropertySource;

@PropertySource(value = "classpath:build.properties", ignoreResourceNotFound = true)
@PropertySource(value = "classpath:application.properties")
@PropertySource(value = "classpath:application-user.properties", ignoreResourceNotFound = true)

//@EnableConfigurationProperties(KeyCloakProperties.class)
@SpringBootApplication
public class ApikeyApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder();
        builder.sources(ApikeyApplication.class).run(args);
    }

}
