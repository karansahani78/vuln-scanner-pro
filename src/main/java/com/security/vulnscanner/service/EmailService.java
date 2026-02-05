package com.security.vulnscanner.service;

import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Service
@Slf4j
public class EmailService {

    @Value("${BREVO_API_KEY}")
    private String apiKey;

    @Value("${MAIL_FROM}")
    private String fromEmail;

    private final OkHttpClient client = new OkHttpClient.Builder()
            .connectTimeout(Duration.ofSeconds(10))
            .readTimeout(Duration.ofSeconds(15))
            .writeTimeout(Duration.ofSeconds(10))
            .build();

    private static final MediaType JSON
            = MediaType.parse("application/json; charset=utf-8");

    public void sendVerificationCode(String email, String code) {

        String jsonBody = """
        {
          "sender": {
            "name": "VulnScanner Pro",
            "email": "%s"
          },
          "to": [
            { "email": "%s" }
          ],
          "subject": "Verify your VulnScanner Pro account",
          "htmlContent": "<h2>Email Verification</h2>
                           <p>Your verification code is <b>%s</b></p>
                           <p>This code is valid for 10 minutes.</p>"
        }
        """.formatted(fromEmail, email, code);

        RequestBody body = RequestBody.create(
                jsonBody.getBytes(StandardCharsets.UTF_8), JSON
        );

        Request request = new Request.Builder()
                .url("https://api.brevo.com/v3/smtp/email")
                .post(body)
                .addHeader("Accept", "application/json")
                .addHeader("api-key", apiKey)
                .build();

        try (Response response = client.newCall(request).execute()) {

            String responseBody = response.body() != null
                    ? response.body().string()
                    : "NO_RESPONSE_BODY";

            if (!response.isSuccessful()) {
                log.error("Brevo email failed | status={} | body={}",
                        response.code(), responseBody);
                throw new RuntimeException("Email sending failed");
            }

            log.info("Verification email sent successfully to {}", email);

        } catch (IOException e) {
            log.error("Brevo email service error", e);
            throw new RuntimeException("Email service unavailable");
        }
    }
}
