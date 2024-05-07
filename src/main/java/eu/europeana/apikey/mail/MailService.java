package eu.europeana.apikey.mail;

import eu.europeana.apikey.exception.SendMailException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import java.util.Objects;


/**
 * Created by luthien on 04/07/2017.
 */
@Component
public class MailService {
    private static final Logger LOG = LogManager.getLogger(MailService.class);

    /**
     * The Email sender.
     */
    @Autowired
    public JavaMailSender emailSender;

    private void sendSimpleMessage(SimpleMailMessage template, String messageBody) throws SendMailException {
        LOG.debug("Sending email ...");
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(Objects.requireNonNull(template.getFrom()));
            message.setBcc(Objects.requireNonNull(template.getBcc()));
            message.setTo(Objects.requireNonNull(template.getTo())[0]);
            message.setSubject(Objects.requireNonNull(template.getSubject()));
            message.setText(messageBody);

            emailSender.send(message);
        } catch (NullPointerException npe) {
            throw new SendMailException("Missing required parameters prevented sending confirmation email", npe);
        } catch (MailException e) {
            throw new SendMailException(String.format("A problem prevented sending a confirmation '%s' email to %s",
                                                      template.getSubject(),
                                                      Objects.requireNonNull(template.getTo())[0]), e);
        }
    }

    /**
     * Send api key email.
     *
     * @param template  the template
     * @param firstName the first name
     * @param lastName  the last name
     * @param apiKey    the api key
     * @throws SendMailException the send mail exception
     */
    public void sendApiKeyEmail(SimpleMailMessage template,
                                String firstName,
                                String lastName,
                                String apiKey) throws SendMailException {
        String messageBody = String.format(Objects.requireNonNull(template.getText()), firstName, lastName, apiKey);
        sendSimpleMessage(template, messageBody);
    }

    /**
     * Send api key and client email.
     *
     * @param template     the template
     * @param firstName    the first name
     * @param lastName     the last name
     * @param apiKey       the api key
     * @param clientSecret the client secret
     * @throws SendMailException the send mail exception
     */
    public void sendApiKeyAndClientEmail(SimpleMailMessage template,
                                         String firstName,
                                         String lastName,
                                         String apiKey,
                                         String clientSecret) throws SendMailException {
        String messageBody = String.format(Objects.requireNonNull(template.getText()),
                                           firstName,
                                           lastName,
                                           apiKey,
                                           clientSecret);
        sendSimpleMessage(template, messageBody);
    }

    /**
     * Send deleted user email boolean.
     *
     * @param template     the template
     * @param today        the today
     * @param email        the email
     * @param kcDeleted    the kc deleted
     * @param setsDeleted  the sets deleted
     * @param inThirtyDays the in thirty days
     * @return the boolean
     */
    public boolean sendDeletedUserEmail(SimpleMailMessage template,
                                        String today,
                                        String email,
                                        String kcDeleted,
                                        String setsDeleted,
                                        String inThirtyDays) {
        String messageBody = String.format(Objects.requireNonNull(template.getText()),
                                           today,
                                           email,
                                           kcDeleted,
                                           setsDeleted,
                                           inThirtyDays);
        try {
            sendSimpleMessage(template, messageBody);
        } catch (SendMailException sme) {
            LOG.error("SendMailException occurred while sending email: {}",sme.getMessage());
            return false;
        }
        return true;
    }

    /**
     * Send user problem email boolean.
     *
     * @param template the template
     * @param today    the today
     * @param userId   the user id
     * @param status   the status
     * @return the boolean
     */
    public boolean sendUserProblemEmail(SimpleMailMessage template,
                                        String today,
                                        String userId,
                                        int status) {

        String messageBody;
        if (status == 0){
            messageBody = String.format(Objects.requireNonNull(template.getText()), today, userId);
        } else {
            messageBody = String.format(Objects.requireNonNull(template.getText()), today, userId, status);
        }
        try {
            sendSimpleMessage(template, messageBody);
        } catch (SendMailException sme) {
            LOG.error("SendMailException occurred while sending email: {}",sme.getMessage());
            return false;
        }
        return true;
    }

}
