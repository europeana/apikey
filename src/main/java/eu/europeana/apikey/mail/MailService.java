package eu.europeana.apikey.mail;

import eu.europeana.apikey.exception.SendMailException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Objects;


/**
 * Created by luthien on 04/07/2017.
 */
@Component
public class MailService {
    private static final Logger LOG = LogManager.getLogger(MailService.class);

    @Autowired
    public JavaMailSender emailSender;

    private void sendSimpleMessage(String from, String[] bcc, String to, String subject, String messageBody) throws
                                                                                                             SendMailException {
        LOG.debug("Sending email ...");
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(from);
            message.setBcc(bcc);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(messageBody);

            emailSender.send(message);
        } catch (MailException e) {
            throw new SendMailException(String.format("A problem prevented sending a confirmation '%s' email to %s",
                                                      subject,
                                                      to), e);
        }
    }

    public void sendSimpleMessageUsingTemplate(String to,
                                               String subject,
                                               SimpleMailMessage template,
                                               String firstName,
                                               String lastName,
                                               String apiKey) throws SendMailException {
        String messageBody = String.format(Objects.requireNonNull(template.getText()),
                                           firstName,
                                           lastName,
                                           apiKey);
        sendSimpleMessage(template.getFrom(), template.getBcc(), to, subject, messageBody);
    }

    public void sendSimpleMessageUsingTemplate(String to,
                                               String subject,
                                               SimpleMailMessage template,
                                               String firstName,
                                               String lastName,
                                               String apiKey,
                                               String clientSecret) throws SendMailException {
        String messageBody = String.format(Objects.requireNonNull(template.getText()),
                                           firstName,
                                           lastName,
                                           apiKey,
                                           clientSecret);
        sendSimpleMessage(template.getFrom(), template.getBcc(), to, subject, messageBody);
    }

    public boolean sendDeletedUserEmail(String to,
                                        String subject,
                                        SimpleMailMessage template,
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
            sendSimpleMessage(template.getFrom(), template.getBcc(), to, subject, messageBody);
        } catch (SendMailException sme) {
            return false;
        }
        return true;
    }

    public boolean sendUserProblemEmail(String to,
                                        String subject,
                                        SimpleMailMessage template,
                                        String today,
                                        String userId,
                                        int status) {
        String messageBody = String.format(Objects.requireNonNull(template.getText()), today, userId, status);
        try {
            sendSimpleMessage(template.getFrom(), template.getBcc(), to, subject, messageBody);
        } catch (SendMailException sme) {
            return false;
        }
        return true;
    }
}
