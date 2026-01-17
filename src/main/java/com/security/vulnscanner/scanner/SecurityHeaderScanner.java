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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class SecurityHeaderScanner implements VulnerabilityScanner {

    private static final Map<String, String> REQUIRED_HEADERS = new HashMap<>() {{
        put("X-Frame-Options", "Protects against clickjacking attacks");
        put("X-Content-Type-Options", "Prevents MIME type sniffing");
        put("Strict-Transport-Security", "Enforces HTTPS connections");
        put("Content-Security-Policy", "Prevents XSS and data injection attacks");
        put("X-XSS-Protection", "Enables browser XSS filtering");
    }};

    @Override
    public List<Vulnerability> scan(String targetUrl, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        log.info("Starting Security Headers scan for: {}", targetUrl);

        try {
            HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(config.getTimeoutSeconds()))
                .build();

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .header("User-Agent", config.getUserAgent())
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Map<String, List<String>> headers = response.headers().map();

            // Check for missing security headers
            for (Map.Entry<String, String> entry : REQUIRED_HEADERS.entrySet()) {
                String headerName = entry.getKey();
                String description = entry.getValue();

                boolean headerFound = headers.keySet().stream()
                    .anyMatch(h -> h.equalsIgnoreCase(headerName));

                if (!headerFound) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle("Missing Security Header: " + headerName);
                    vuln.setDescription("The application does not set the '" + headerName + "' security header. " +
                        description + ". This header is important for protecting against various web attacks.");
                    vuln.setSeverity(determineSeverity(headerName));
                    vuln.setCvssScore(calculateCVSS(headerName));
                    vuln.setCategory("Security Misconfiguration");
                    vuln.setCweId("CWE-16");
                    vuln.setAffectedUrl(targetUrl);
                    vuln.setEvidence("Security header '" + headerName + "' is not present in the response");
                    vuln.setRemediation(getRemediation(headerName));
                    vuln.setReferences("OWASP Secure Headers Project\n" +
                        "https://owasp.org/www-project-secure-headers/");
                    
                    vulnerabilities.add(vuln);
                    log.info("Missing security header detected: {}", headerName);
                }
            }

            // Check for insecure cookies (IMPROVED: Filter analytics/tracking cookies)
            List<String> setCookieHeaders = headers.get("set-cookie");
            if (setCookieHeaders != null) {
                for (String cookie : setCookieHeaders) {
                    String cookieLower = cookie.toLowerCase();
                    
                    // Skip analytics and tracking cookies (not security issues)
                    if (isAnalyticsOrTrackingCookie(cookie)) {
                        continue;
                    }
                    
                    // Only flag actual session/authentication cookies without security flags
                    boolean isSessionCookie = cookieLower.contains("session") || 
                                            cookieLower.contains("auth") ||
                                            cookieLower.contains("token") ||
                                            cookieLower.contains("csrf");
                    
                    boolean hasSecure = cookieLower.contains("secure");
                    boolean hasHttpOnly = cookieLower.contains("httponly");
                    
                    // Only create vulnerability for security-critical cookies
                    if (isSessionCookie && (!hasSecure || !hasHttpOnly)) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("Insecure Session Cookie Configuration");
                        vuln.setDescription("Security-critical cookies are set without proper security flags (Secure, HttpOnly). " +
                            "This makes them vulnerable to interception and XSS attacks.");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setCvssScore(5.3);
                        vuln.setCategory("Security Misconfiguration");
                        vuln.setCweId("CWE-614");
                        vuln.setAffectedUrl(targetUrl);
                        vuln.setEvidence("Session cookie without Secure/HttpOnly flags: " + 
                            cookie.substring(0, Math.min(100, cookie.length())));
                        vuln.setRemediation("Set Secure and HttpOnly flags on all session/authentication cookies:\n" +
                            "- Secure: Ensures cookie is only sent over HTTPS\n" +
                            "- HttpOnly: Prevents JavaScript access to cookies\n" +
                            "- SameSite: Prevents CSRF attacks\n" +
                            "Example: Set-Cookie: sessionId=value; Secure; HttpOnly; SameSite=Strict");
                        vuln.setReferences("OWASP Session Management Cheat Sheet");
                        
                        vulnerabilities.add(vuln);
                        break; // Report once per target
                    }
                }
            }

        } catch (Exception e) {
            log.error("Error during Security Headers scan: {}", e.getMessage());
        }

        return vulnerabilities;
    }

    private Vulnerability.Severity determineSeverity(String headerName) {
        return switch (headerName) {
            case "Content-Security-Policy" -> Vulnerability.Severity.HIGH;
            case "Strict-Transport-Security" -> Vulnerability.Severity.HIGH;
            case "X-Frame-Options" -> Vulnerability.Severity.MEDIUM;
            case "X-Content-Type-Options" -> Vulnerability.Severity.LOW;
            case "X-XSS-Protection" -> Vulnerability.Severity.LOW;
            default -> Vulnerability.Severity.INFO;
        };
    }

    private double calculateCVSS(String headerName) {
        return switch (headerName) {
            case "Content-Security-Policy" -> 6.5;
            case "Strict-Transport-Security" -> 6.1;
            case "X-Frame-Options" -> 4.3;
            case "X-Content-Type-Options" -> 3.1;
            case "X-XSS-Protection" -> 3.1;
            default -> 2.0;
        };
    }

    private String getRemediation(String headerName) {
        return switch (headerName) {
            case "Content-Security-Policy" ->
                "Add Content-Security-Policy header to prevent XSS and injection attacks:\n" +
                "Example: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'";
            case "Strict-Transport-Security" ->
                "Add Strict-Transport-Security header to enforce HTTPS:\n" +
                "Example: Strict-Transport-Security: max-age=31536000; includeSubDomains";
            case "X-Frame-Options" ->
                "Add X-Frame-Options header to prevent clickjacking:\n" +
                "Example: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN";
            case "X-Content-Type-Options" ->
                "Add X-Content-Type-Options header to prevent MIME sniffing:\n" +
                "Example: X-Content-Type-Options: nosniff";
            case "X-XSS-Protection" ->
                "Add X-XSS-Protection header (note: CSP is preferred):\n" +
                "Example: X-XSS-Protection: 1; mode=block";
            default -> "Add the missing security header to your response.";
        };
    }

    @Override
    public String getScannerName() {
        return "Security Headers Scanner";
    }

    @Override
    public boolean isApplicable(String targetUrl) {
        return targetUrl.startsWith("http://") || targetUrl.startsWith("https://");
    }
    
    /**
     * Detect analytics and tracking cookies to avoid false positives
     * These are not security issues and should not be flagged
     */
    private boolean isAnalyticsOrTrackingCookie(String cookie) {
        String cookieLower = cookie.toLowerCase();
        
        // Common analytics/tracking cookie patterns
        String[] trackingPatterns = {
            "_ga",          // Google Analytics
            "_gid",         // Google Analytics
            "_gat",         // Google Analytics
            "_gcl_",        // Google Click Identifier
            "_fbp",         // Facebook Pixel
            "_fbc",         // Facebook Click ID
            "_hjid",        // Hotjar
            "_hjincludedInPageviewSample",  // Hotjar
            "utm_",         // UTM parameters
            "__cfduid",     // Cloudflare
            "__cf_bm",      // Cloudflare Bot Management
            "_mkto_trk",    // Marketo
            "vuid",         // Vimeo
            "_pinterest_",  // Pinterest
            "_twitter_",    // Twitter
            "ide",          // Google DoubleClick
            "test_cookie",  // Google test cookie
            "nid",          // Google
            "consent"       // Google consent
        };
        
        for (String pattern : trackingPatterns) {
            if (cookieLower.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        
        return false;
    }
}
