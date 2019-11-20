package eu.europeana.apikey.mail;

import eu.europeana.apikey.exception.SendMailException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.File;


/**
 * Created by luthien on 04/07/2017.
 */
@Component
public class MailService {
    private static final Logger LOG = LogManager.getLogger(MailService.class);

    @Autowired
    public JavaMailSender emailSender;

    private void sendSimpleMessage(String from, String to, String subject, String messageBody) throws SendMailException {
        LOG.debug("send email ...");
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(from);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(messageBody);

            emailSender.send(message);
        } catch (MailException e) {
            LOG.error("Exception occurred sending email message {} ", e.getMessage());
            throw new SendMailException(e.getMessage(), to, subject);
        }
    }

    public void sendSimpleMessageUsingTemplate(String to,
                                               String subject,
                                               SimpleMailMessage template,
                                               String... templateArgs) throws SendMailException {
        String messageBody = String.format(template.getText(), (String[]) templateArgs);
        sendSimpleMessage(template.getFrom(), to, subject, messageBody);
    }

    public void sendMessageWithAttachment(String to,
                                          String subject,
                                          String messageBody,
                                          String pathToAttachment) {
        LOG.debug("send email with attachment ...");
        try {
            MimeMessage message = emailSender.createMimeMessage();
            // pass 'true' to the constructor to create a multipart message
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(messageBody);

            FileSystemResource file = new FileSystemResource(new File(pathToAttachment));
            helper.addAttachment("Invoice", file);

            emailSender.send(message);
        } catch (MessagingException e) {
            LOG.error("Exception occurred sending email message with attachment {} ", e.getMessage());
        }
    }
}
