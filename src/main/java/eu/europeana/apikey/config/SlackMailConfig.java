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

    private static final String NO_ACTION_BUT_LOGGED = "carrying out this request.\nNo action was taken.\\nThe user token has been logged in Kibana.";
    private static final String REQUEST_RECEIVED     = "On %s, a request was received to remove user account with ID %s.\n\n";

    @Value("${keycloak.user.slack.from}")
    private String sentFrom;

    @Value("${keycloak.user.slack.bcc}")
    private String copyTo;

    @Bean("userDeletedTemplate")
    public SimpleMailMessage userDeletedSlackMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setSubject("Auth user service: result of user delete request");
        message.setText("On %s, user %s has requested to remove their account.\n\n" +
                        "This has just been done automatically for those systems marked with [✓]:\n\n" +
                        "[%s] Keycloak\n" + "[%s] The User Sets Api\n" + "[✘] The recommendation engine\n" +
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

    @Bean("userNotFoundTemplate")
    public SimpleMailMessage userNotFoundSlackMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText(REQUEST_RECEIVED +
                        "This userID could not be found in Keycloak (HTTP status %d), which might indicate a problem " +
                        "with the token used to send the request. Therefore the token has been logged in Kibana.");
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }

    @Bean("kcCommProblemTemplate")
    public SimpleMailMessage kcCommProblemSlackMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText(REQUEST_RECEIVED + "There was a problem connecting to Keycloak (HTTP status %d), preventing " +
                        NO_ACTION_BUT_LOGGED);
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }

    @Bean("forbiddenTemplate")
    public SimpleMailMessage kcForbiddenSlackMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText(REQUEST_RECEIVED + "An authorisation problem for the embedded Keycloak User prevented " +
                        NO_ACTION_BUT_LOGGED);
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }

    @Bean("unavailableTemplate")
    public SimpleMailMessage unavailableSlackMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText(REQUEST_RECEIVED + "\"A server error occurred which prevented  " + NO_ACTION_BUT_LOGGED);
        message.setFrom(sentFrom);
        if (StringUtils.isNotEmpty(copyTo)) {
            message.setBcc(copyTo);
        }
        return message;
    }

    }
