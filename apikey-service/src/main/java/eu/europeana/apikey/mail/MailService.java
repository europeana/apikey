package eu.europeana.apikey.mail;

import org.springframework.mail.SimpleMailMessage;

/**
 * Created by luthien on 04/07/2017.
 */
public interface MailService {
    void sendSimpleMessage(String from,
                           String to,
                           String subject,
                           String messageBody);
    void sendSimpleMessageUsingTemplate(String to,
                                        String subject,
                                        SimpleMailMessage template,
                                        String ...templateArgs);
    void sendMessageWithAttachment(String to,
                                   String subject,
                                   String messageBody,
                                   String pathToAttachment);
}