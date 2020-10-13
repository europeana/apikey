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

        message.setText("User %s has requested to remove their account.\\n\\n" +
                        "This has just been done for the systems marked with [V]:\\n\\n" +
                        "[%s] Keycloak\\n" +
                        "[%s] The User Sets Api\\n" +
                        "[X] The recommendation engine\\n" +
                        "[X] Mailchimp%n\\n" +
                        "The date of their request is %tc. \n" +
                        "Please remove their account from the services marked with [X] within 30 days.\\n\\n\\n" +
                        "(this email was sent by the Delete User Service because sending message via HTTP request failed)");
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }
}
