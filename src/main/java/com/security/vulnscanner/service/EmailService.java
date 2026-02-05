package com.security.vulnscanner.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    public void sendVerificationCode(String email, String code) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom("codewithkaran723@gmail.com");
            message.setTo(email);
            message.setSubject("Verify your VulnScanner Pro account");
            message.setText("Your verification code is: " + code + "\nValid for 10 minutes.");

            mailSender.send(message);

        } catch (Exception e) {
            log.error("Email sending failed", e);
            throw new RuntimeException("Email service unavailable");
        }
    }
}
