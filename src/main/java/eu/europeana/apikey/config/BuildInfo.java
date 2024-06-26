package eu.europeana.apikey.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

/**
 * Makes build information and the application name and description from the project's pom.xml available.
 * While generating a war file this data is written automatically to the build.properties file which is read here.
 * Note that the same information is also available in the Spring-Boot /actuator/info endpoint
 */
@Configuration
@PropertySource("classpath:build.properties")
public class BuildInfo {

    @Value("${info.app.name}")
    private String appName;

    @Value("${info.app.version}")
    private String appVersion;

    @Value("${info.app.description}")
    private String appDescription;

    @Value("${info.build.number}")
    private String buildNumber;

    /**
     * Gets app name.
     *
     * @return the app name
     */
    public String getAppName() {
        return appName;
    }

    /**
     * Gets app description.
     *
     * @return the app description
     */
    public String getAppDescription() {
        return appDescription;
    }

    /**
     * Gets app version.
     *
     * @return the app version
     */
    public String getAppVersion() {
        return appVersion;
    }

    /**
     * Gets build number.
     *
     * @return the build number
     */
    public String getBuildNumber() {
        return buildNumber;
    }
}
