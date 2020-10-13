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
class SlackMailConfig extends WebMvcConfigurerAdapter {

    @Value("${keycloak.user.slack.from}")
    private String sentFrom;

    @Value("${keycloak.user.slack.bcc}")
    private String copyTo;

    @Bean("slackMail")
    public SimpleMailMessage userDeletedSlackMail() {
        SimpleMailMessage message = new SimpleMailMessage();

        message.setText("On %s, user %s has requested to remove their account.\n\n" +
                        "This has just been done automatically for those systems marked with [✓]:\n\n" +
                        "[%s] Keycloak\n" +
                        "[%s] The User Sets Api\n" +
                        "[✘] The recommendation engine\n" +
                        "[✘] Mailchimp%n\n\n" +
                        "From the remaining systems (marked with [✘] above) their account should be removed " +
                        "within 30 days (before %s).\n\n\n" +
                        "(Please note that this email was sent by the Delete User Service only after sending this " +
                        "message via the regular HTTP request failed: please check why this happened)");
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }
}
