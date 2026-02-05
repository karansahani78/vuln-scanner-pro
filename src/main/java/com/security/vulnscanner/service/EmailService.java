package com.security.vulnscanner.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    @Value("${BREVO_API_KEY}")
    private String apiKey;

    @Value("${MAIL_FROM}")
    private String fromEmail;

    private final OkHttpClient client = new OkHttpClient();

    public void sendVerificationCode(String email, String code) {

        String jsonBody = """
        {
          "sender": {"name": "VulnScanner Pro", "email": "%s"},
          "to": [{"email": "%s"}],
          "subject": "Verify your VulnScanner Pro account",
          "htmlContent": "<h2>Email Verification</h2><p>Your verification code is <b>%s</b></p><p>Valid for 10 minutes.</p>"
        }
        """.formatted(fromEmail, email, code);

        RequestBody body = RequestBody.create(
                jsonBody, MediaType.parse("application/json"));

        Request request = new Request.Builder()
                .url("https://api.brevo.com/v3/smtp/email")
                .post(body)
                .addHeader("accept", "application/json")
                .addHeader("api-key", apiKey)
                .addHeader("content-type", "application/json")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                log.error("Brevo email failed: {}", response.body().string());
                throw new RuntimeException("Email sending failed");
            }
            log.info("Verification email sent to {}", email);
        } catch (IOException e) {
            log.error("Email service error", e);
            throw new RuntimeException("Email service unavailable");
        }
    }
}
