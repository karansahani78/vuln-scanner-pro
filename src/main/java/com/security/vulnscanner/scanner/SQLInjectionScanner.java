package com.security.vulnscanner.scanner;

import com.security.vulnscanner.model.Vulnerability;
import com.security.vulnscanner.service.VulnerabilityValidator;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class SQLInjectionScanner implements VulnerabilityScanner {
    
    private final VulnerabilityValidator validator;

    private static final String[] SQL_PAYLOADS = {
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "1' UNION SELECT NULL--",
        "' AND 1=1--",
        "' AND 1=2--"
    };

    private static final String[] SQL_ERROR_PATTERNS = {
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "SQLite",
        "Microsoft SQL",
        "ODBC",
        "SQLException"
    };

    @Override
    public List<Vulnerability> scan(String targetUrl, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        log.info("Starting SQL Injection scan for: {}", targetUrl);

        try {
            HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(config.getTimeoutSeconds()))
                .build();

            for (String payload : SQL_PAYLOADS) {
                try {
                    String testUrl = buildTestUrl(targetUrl, payload);
                    
                    HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(testUrl))
                        .header("User-Agent", config.getUserAgent())
                        .timeout(Duration.ofSeconds(10))
                        .GET()
                        .build();

                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    String body = response.body();

                    // Check for SQL error patterns
                    for (String pattern : SQL_ERROR_PATTERNS) {
                        if (body.contains(pattern)) {
                            // Validate with multiple techniques
                            VulnerabilityValidator.ValidationResult validationResult = 
                                validator.validateSQLi(testUrl, payload, config.getUserAgent());
                            
                            if (validationResult.isConfirmed()) {
                                Vulnerability vuln = new Vulnerability();
                                vuln.setTitle("SQL Injection Vulnerability CONFIRMED");
                                vuln.setDescription(String.format(
                                    "The application is vulnerable to SQL injection attacks (Confidence: %d%%). " +
                                    "SQL error messages were detected and exploitation was confirmed through multiple validation techniques. " +
                                    "An attacker can potentially read, modify, or delete database contents.",
                                    validationResult.getConfidence()));
                                vuln.setSeverity(Vulnerability.Severity.CRITICAL);
                                vuln.setCvssScore(9.8);
                                vuln.setCategory("Injection");
                                vuln.setCweId("CWE-89");
                                vuln.setAffectedUrl(testUrl);
                                vuln.setEvidence(String.format(
                                    "SQL error pattern detected: %s\n\nValidation Evidence:\n%s", 
                                    pattern,
                                    String.join("\n", validationResult.getEvidence())));
                                vuln.setRemediation("IMMEDIATE ACTION REQUIRED:\n\n" +
                                    "1. USE PARAMETERIZED QUERIES (Prepared Statements)\n" +
                                    "   Example for Spring Boot/JDBC:\n" +
                                    "   ```java\n" +
                                    "   String sql = \"SELECT * FROM users WHERE name = ?\";\n" +
                                    "   jdbcTemplate.query(sql, new UserRowMapper(), userName);\n" +
                                    "   ```\n\n" +
                                    "2. Use ORM frameworks properly (Hibernate, JPA)\n" +
                                    "3. Implement input validation and sanitization\n" +
                                    "4. Apply principle of least privilege for database accounts\n" +
                                    "5. Implement WAF (Web Application Firewall)\n" +
                                    "6. Enable database query logging for monitoring\n\n" +
                                    "DO NOT use string concatenation for SQL queries!");
                                vuln.setReferences("OWASP Top 10 - A03:2021 Injection\n" +
                                    "CWE-89: SQL Injection\n" +
                                    "https://owasp.org/www-community/attacks/SQL_Injection\n" +
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html");
                                
                                vulnerabilities.add(vuln);
                                log.warn("SQL Injection CONFIRMED at: {} (Confidence: {}%)", 
                                    testUrl, validationResult.getConfidence());
                                break; // Don't report duplicate for same URL
                            } else {
                                log.debug("SQL Injection suspected but not confirmed at: {} (Confidence: {}%)",
                                    testUrl, validationResult.getConfidence());
                            }
                        }
                    }
                } catch (Exception e) {
                    log.debug("Request failed for payload: {} - {}", payload, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("Error during SQL injection scan: {}", e.getMessage());
        }

        return vulnerabilities;
    }

    private String buildTestUrl(String baseUrl, String payload) {
        try {
            String encodedPayload = java.net.URLEncoder.encode(payload, "UTF-8");
            if (baseUrl.contains("?")) {
                // Add payload to existing query parameters
                return baseUrl + "&test=" + encodedPayload;
            } else {
                return baseUrl + "?test=" + encodedPayload;
            }
        } catch (Exception e) {
            log.error("Error encoding payload: {}", e.getMessage());
            return baseUrl;
        }
    }

    @Override
    public String getScannerName() {
        return "SQL Injection Scanner";
    }

    @Override
    public boolean isApplicable(String targetUrl) {
        return targetUrl.startsWith("http://") || targetUrl.startsWith("https://");
    }
}
