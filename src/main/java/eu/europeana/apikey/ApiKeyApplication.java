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
/**
 * no comment
 */
public class ApiKeyApplication extends SpringBootServletInitializer {
    /**
     *
     * @param args
     */
    public static void main(String[] args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder();
        builder.sources(ApiKeyApplication.class).run(args);
    }

}
