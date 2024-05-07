package eu.europeana.apikey.config;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * The type Apikey mail config.
 */
@Configuration
@EnableWebMvc
class ApikeyMailConfig {

    private static final String APIKEY_USAGE = "The API key can be used for regular API request, see https://pro.europeana.eu/resources/apis/intro#access";
    private static final String SECRET_USAGE = "while the API key and Secret key together authenticate the Keycloak Client used to authenticate for " +
                                               "specific API methods that require additional authentication.";
    private static final String MESSAGEFOOTER =
            "%n%n" +
            "Please keep a safe record of these key(s) and do not share them with third parties or expose it in user " +
            "interfaces or in markup, as the API key(s) are confidential and are for use by the client or user only." +
            "%n%n" +
            "Our technical documentation for all APIs is available at https://pro.europeana.eu/resources/apis which " +
            "includes an API console for testing and community developed libraries for a variety of programming languages." +
            "%n%n" +
            "Please join us in the Europeana API Forum (https://groups.google.com/forum/?pli=1#!forum/europeanaapi) " +
            "- to ask questions to us and other developers and to give us your feedback on our API. " +
            "You can also contact us directly by mailing api@europeana.eu " +
            "and we would be especially grateful if you would let us know about your implementation so that we can " +
            "feature it in our application gallery on Europeana Pro - https://pro.europeana.eu/resources/apps." +
            "%n%n" + "Best regards," + "%n" + "The Europeana API Team";

    private static final String SEPARATOR = "===========================%n";
    private static final String LONGSEPARATOR = "====================================================%n";
    private static final String LONGERSEPARATOR = "================================================================%n";

    @Value("${europeana.mail.from}")
    private String sentFrom;

    @Value("${europeana.mail.bcc}")
    private String copyTo;

    /**
     * Apikey created mail simple mail message.
     *
     * @return the simple mail message
     */
    @Bean("apikeyTemplate")
    public SimpleMailMessage apikeyCreatedMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setSubject("Your Europeana API key");
        message.setText("Dear %s %s,%n%nThank you for registering for the Europeana API." + "%n" +
                        "This is your Europeana API key: %n%n" +
                        SEPARATOR +
                        "API key: \t%s %n" +
                        SEPARATOR + "%n%n" +
                        APIKEY_USAGE + "." +
                        MESSAGEFOOTER);
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }

    /**
     * Apikey and client created mail simple mail message.
     *
     * @return the simple mail message
     */
    @Bean("apikeyAndClientTemplate")
    public SimpleMailMessage apikeyAndClientCreatedMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setSubject("Your Europeana API keys");
        message.setText("Dear %s %s,%n%nThank you for registering for the Europeana API." + "%n" +
                        "These are your Europeana API keys: %n%n" +
                        LONGSEPARATOR +
                        "API key: \t\t%s %n" +
                        "Secret key: \t%s %n" +
                        LONGSEPARATOR + "%n%n" +
                        APIKEY_USAGE + ", " + SECRET_USAGE +
                        MESSAGEFOOTER);
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }

    /**
     * Client added mail simple mail message.
     *
     * @return the simple mail message
     */
    @Bean("clientTemplate")
    public SimpleMailMessage clientAddedMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setSubject("Keycloak authentication was added to your Europeana API key");
        message.setText("Dear %s %s,%n%nThank you for requesting a secret key for the Europeana API." + "%n" +
                        "This secret key is intended to be used together with your existing Europeana API key:%n%n" +
                        LONGERSEPARATOR +
                        "Your existing API key is: \t%s %n" +
                        "Your new secret key is: \t%s %n" +
                        LONGERSEPARATOR + "%n%n" +
                        APIKEY_USAGE + ", " + SECRET_USAGE +
                        MESSAGEFOOTER);
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }

}
