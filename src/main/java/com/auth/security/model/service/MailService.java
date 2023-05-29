package com.auth.security.model.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class MailService {
    /*
     * The Spring Framework provides an easy abstraction for sending email by using
     * the JavaMailSender interface, and Spring Boot provides auto-configuration for
     * it as well as a starter module.
     */
    private JavaMailSender javaMailSender;
    @Value("${spring.mail.username}")
    private String from;

    /**
     *
     * @param javaMailSender
     */
    @Autowired
    public MailService(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }

    /**
     * This function is used to send mail without attachment.
     * @param email email address to be sent
     * @param code unique code for verification
     * @param subject subject of the mail
     * @param body text body of the mail
     * @throws MailException
     */

    public void sendEmail(String email, int code, String subject, String body) throws MailException {

        /*
         * This JavaMailSender Interface is used to send Mail in Spring Boot. This
         * JavaMailSender extends the MailSender Interface which contains send()
         * function. SimpleMailMessage Object is required because send() function uses
         * object of SimpleMailMessage as a Parameter
         */

        SimpleMailMessage mail = new SimpleMailMessage();
        mail.setFrom(from);
        mail.setTo(email);
        mail.setSubject(subject);
        mail.setText(body + " " +code);

        /*
         * This send() contains an Object of SimpleMailMessage as an Parameter
         */
        javaMailSender.send(mail);
    }

    /**
     * This function is used to send mail that contains a attachment.
     *
     * @param email email address to be sent
     * @param code unique code for verification
     * @param subject subject of the mail
     * @param body text body of the mail
     * @param attachment url of the document to be attached
     * @throws MailException
     * @throws MessagingException
     */
    public void sendEmailWithAttachment(String email, int code, String subject, String body, String attachment) throws MailException, MessagingException {

        MimeMessage mimeMessage = javaMailSender.createMimeMessage();

        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);
        helper.setFrom(from);
        helper.setTo(email);
        helper.setSubject(subject);
        helper.setText(body + " " + code);

        ClassPathResource classPathResource = new ClassPathResource(attachment);
        helper.addAttachment(classPathResource.getFilename(), classPathResource);

        javaMailSender.send(mimeMessage);
    }

}
