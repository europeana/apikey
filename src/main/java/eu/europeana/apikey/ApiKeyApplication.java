/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.PropertySource;

@PropertySource(value = "classpath:build.properties", ignoreResourceNotFound = true)
@SpringBootApplication
        //(scanBasePackages = {"eu.europeana.api", "eu.europeana.apikey"})
public class ApiKeyApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder();
        builder.sources(ApiKeyApplication.class).run(args);
    }

}
