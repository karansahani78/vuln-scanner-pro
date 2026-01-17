package com.security.vulnscanner.scanner;

import com.security.vulnscanner.model.Vulnerability;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
public class XSSScanner implements VulnerabilityScanner {

    private static final String[] XSS_PAYLOADS = {
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<body onload=alert('XSS')>"
    };

    @Override
    public List<Vulnerability> scan(String targetUrl, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        log.info("Starting XSS scan for: {}", targetUrl);

        try {
            HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(config.getTimeoutSeconds()))
                .build();

            for (String payload : XSS_PAYLOADS) {
                String testUrl = buildTestUrl(targetUrl, payload);
                
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(testUrl))
                    .header("User-Agent", config.getUserAgent())
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();

                try {
                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    String body = response.body();

                    // Check if payload is reflected in response
                    if (body.contains(payload) || body.contains(payload.toLowerCase())) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("Cross-Site Scripting (XSS) Vulnerability");
                        vuln.setDescription("The application reflects user input without proper encoding or validation, " +
                            "making it vulnerable to Cross-Site Scripting (XSS) attacks. Attackers can inject " +
                            "malicious scripts that execute in victims' browsers.");
                        vuln.setSeverity(Vulnerability.Severity.HIGH);
                        vuln.setCvssScore(7.3);
                        vuln.setCategory("Cross-Site Scripting");
                        vuln.setCweId("CWE-79");
                        vuln.setAffectedUrl(testUrl);
                        vuln.setEvidence("Payload reflected in response: " + payload.substring(0, Math.min(50, payload.length())));
                        vuln.setRemediation("1. Implement output encoding for all user-controlled data\n" +
                            "2. Use Content Security Policy (CSP) headers\n" +
                            "3. Validate and sanitize all user inputs\n" +
                            "4. Use frameworks that auto-escape XSS by default\n" +
                            "5. Set HTTPOnly and Secure flags on cookies");
                        vuln.setReferences("OWASP Top 10 - A03:2021 Injection\n" +
                            "CWE-79: Cross-site Scripting\n" +
                            "https://owasp.org/www-community/attacks/xss/");
                        
                        vulnerabilities.add(vuln);
                        log.warn("XSS vulnerability found at: {}", testUrl);
                        break; // Don't report duplicate for same URL
                    }
                } catch (Exception e) {
                    log.debug("Request failed for XSS payload: {} - {}", payload, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("Error during XSS scan: {}", e.getMessage());
        }

        return vulnerabilities;
    }

    private String buildTestUrl(String baseUrl, String payload) {
        try {
            if (baseUrl.contains("?")) {
                return baseUrl + "&xss=" + java.net.URLEncoder.encode(payload, "UTF-8");
            } else {
                return baseUrl + "?xss=" + java.net.URLEncoder.encode(payload, "UTF-8");
            }
        } catch (Exception e) {
            return baseUrl;
        }
    }

    @Override
    public String getScannerName() {
        return "XSS Scanner";
    }

    @Override
    public boolean isApplicable(String targetUrl) {
        return targetUrl.startsWith("http://") || targetUrl.startsWith("https://");
    }
}
