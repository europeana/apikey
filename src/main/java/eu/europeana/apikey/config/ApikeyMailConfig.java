package eu.europeana.apikey.config;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
@EnableWebMvc
class ApikeyMailConfig extends WebMvcConfigurerAdapter {

    private static final String MESSAGEFOOTER =
            "%n%n" +
            "Please keep a safe record of these keys and do not share them with third parties or expose it in user " +
            "interfaces or in markup, as the API keys are confidential and are for use by the client or user only." +
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

    @Value("${europeana.mail.from}")
    private String sentFrom;

    @Value("${europeana.mail.bcc}")
    private String copyTo;

    @Bean("apikeyMail")
    public SimpleMailMessage apikeyCreatedMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText("Dear %s %s,%n%nThank you for registering for the Europeana API." + "%n%n" +
                        "This is your Europeana API key: %n" +
                        SEPARATOR +
                        "API key: \t\t%s %n" +
                        SEPARATOR + "%n%n" +
                        "The API key be used for regular API request, see https://pro.europeana.eu/resources/apis/intro#access." +
                        MESSAGEFOOTER);
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }

    @Bean("apikeyAndClientMail")
    public SimpleMailMessage apikeyAndClientCreatedMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText("Dear %s %s,%n%nThank you for registering for the Europeana API." + "%n%n" +
                        "These are your Europeana API keys: %n" +
                        SEPARATOR +
                        "API key: \t\t%s %n" +
                        "Secret key: \t%s %n" +
                        SEPARATOR + "%n%n" +
                        "The API key alone can be used for regular API request, see https://pro.europeana.eu/resources/apis/intro#access." +
                        "The API key and Secret key together identify the Keycloak Client used to authenticate for specific API methods that " +
                        "require additional authentication." +
                        MESSAGEFOOTER);
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }

    @Bean("clientAddedMail")
    public SimpleMailMessage clientAddedMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText("Dear %s %s,%n%nThank you for requesting a secret key for the Europeana API." + "%n%n" +
                        "This secret key is to be used with your existing Europeana API key%n" +
                        SEPARATOR +
                        "Your existing API key is: \t%s %n" +
                        "Your new secret key is: \t%s %n" +
                        SEPARATOR + "%n%n" +
                        "The API key alone can be used for regular API request, see https://pro.europeana.eu/resources/apis/intro#access." +
                        "The API key and Secret key together identify the Keycloak Client used to authenticate for specific API methods that " +
                        "require additional authentication." +
                        MESSAGEFOOTER);
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }

}
