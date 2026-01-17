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
public class APISecurityScanner implements VulnerabilityScanner {
    
    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build();
    
    @Override
    public List<Vulnerability> scan(String targetUrl, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        log.info("Starting API security scan for: {}", targetUrl);
        
        try {
            // Only scan API endpoints
            if (!targetUrl.contains("/api/") && !isAPIEndpoint(targetUrl)) {
                log.debug("Skipping non-API endpoint: {}", targetUrl);
                return vulnerabilities;
            }
            
            // Test for rate limiting
            vulnerabilities.addAll(testRateLimiting(targetUrl, config));
            
            // Test for excessive data exposure
            vulnerabilities.addAll(testExcessiveDataExposure(targetUrl, config));
            
            // Test for CORS misconfiguration
            vulnerabilities.addAll(testCORSMisconfiguration(targetUrl, config));
            
            // Test for API versioning issues
            vulnerabilities.addAll(testAPIVersioning(targetUrl, config));
            
            // Test for insecure API documentation
            vulnerabilities.addAll(testAPIDocumentation(targetUrl, config));
            
        } catch (Exception e) {
            log.error("Error during API security scan: {}", e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> testRateLimiting(String targetUrl, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            log.debug("Testing rate limiting for: {}", targetUrl);
            
            int successfulRequests = 0;
            long startTime = System.currentTimeMillis();
            
            // Send 50 rapid requests
            for (int i = 0; i < 50; i++) {
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .header("User-Agent", config.getUserAgent())
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
                
                try {
                    HttpResponse<String> response = httpClient.send(request, 
                        HttpResponse.BodyHandlers.ofString());
                    
                    if (response.statusCode() != 429) { // 429 = Too Many Requests
                        successfulRequests++;
                    }
                } catch (Exception e) {
                    // Ignore individual request failures
                }
            }
            
            long duration = System.currentTimeMillis() - startTime;
            
            if (successfulRequests > 40) { // More than 80% requests succeeded
                Vulnerability vuln = new Vulnerability();
                vuln.setTitle("Missing or Weak Rate Limiting");
                vuln.setDescription(String.format(
                    "The API endpoint does not implement adequate rate limiting. " +
                    "%d out of 50 rapid requests succeeded in %.2f seconds. " +
                    "This makes the endpoint vulnerable to brute force attacks, credential stuffing, " +
                    "and denial of service.",
                    successfulRequests, duration / 1000.0));
                vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                vuln.setCvssScore(5.3);
                vuln.setCategory("API Security");
                vuln.setCweId("CWE-770");
                vuln.setAffectedUrl(targetUrl);
                vuln.setEvidence(String.format(
                    "Rapid fire test: %d/%d requests succeeded\nDuration: %.2fs\nNo 429 (Rate Limit) responses received",
                    successfulRequests, 50, duration / 1000.0));
                vuln.setRemediation("IMPLEMENT RATE LIMITING:\n\n" +
                    "For Spring Boot:\n" +
                    "```java\n" +
                    "@Component\n" +
                    "public class RateLimitFilter extends OncePerRequestFilter {\n" +
                    "    private final RateLimiter rateLimiter = RateLimiter.create(10.0); // 10 requests per second\n" +
                    "    \n" +
                    "    @Override\n" +
                    "    protected void doFilterInternal(HttpServletRequest request, \n" +
                    "                                    HttpServletResponse response, \n" +
                    "                                    FilterChain filterChain) throws ServletException, IOException {\n" +
                    "        if (!rateLimiter.tryAcquire()) {\n" +
                    "            response.setStatus(429);\n" +
                    "            response.getWriter().write(\"Too many requests\");\n" +
                    "            return;\n" +
                    "        }\n" +
                    "        filterChain.doFilter(request, response);\n" +
                    "    }\n" +
                    "}\n" +
                    "```\n\n" +
                    "Or use libraries:\n" +
                    "- Bucket4j for Spring Boot\n" +
                    "- Redis for distributed rate limiting\n" +
                    "- API Gateway rate limiting (AWS, Azure, Kong)");
                vuln.setReferences("OWASP API Security Top 10 - API4:2023 Unrestricted Resource Consumption");
                
                vulnerabilities.add(vuln);
                log.warn("Rate limiting issue found at: {}", targetUrl);
            }
            
        } catch (Exception e) {
            log.error("Error testing rate limiting: {}", e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> testExcessiveDataExposure(String targetUrl, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .header("User-Agent", config.getUserAgent())
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, 
                HttpResponse.BodyHandlers.ofString());
            
            String body = response.body().toLowerCase();
            
            // Check for sensitive data patterns in response
            List<String> exposedData = new ArrayList<>();
            
            if (body.contains("password") && !body.contains("password_hash")) {
                exposedData.add("password fields");
            }
            if (body.matches(".*\\b\\d{3}-\\d{2}-\\d{4}\\b.*")) {
                exposedData.add("potential SSN");
            }
            if (body.contains("credit_card") || body.contains("card_number")) {
                exposedData.add("credit card references");
            }
            if (body.contains("api_key") || body.contains("secret_key")) {
                exposedData.add("API keys");
            }
            if (body.contains("\"token\"") && !body.contains("csrf")) {
                exposedData.add("authentication tokens");
            }
            
            if (!exposedData.isEmpty()) {
                Vulnerability vuln = new Vulnerability();
                vuln.setTitle("Excessive Data Exposure in API Response");
                vuln.setDescription(
                    "The API returns more data than necessary, potentially exposing sensitive information. " +
                    "Detected exposure of: " + String.join(", ", exposedData) + ". " +
                    "APIs should only return the minimum data required for the client operation.");
                vuln.setSeverity(Vulnerability.Severity.HIGH);
                vuln.setCvssScore(7.5);
                vuln.setCategory("API Security");
                vuln.setCweId("CWE-200");
                vuln.setAffectedUrl(targetUrl);
                vuln.setEvidence("Sensitive data patterns found: " + String.join(", ", exposedData));
                vuln.setRemediation("IMPLEMENT DATA FILTERING:\n\n" +
                    "1. Use DTOs (Data Transfer Objects) to control response shape\n" +
                    "2. Implement field-level filtering\n" +
                    "3. Never return full database models\n" +
                    "4. Use @JsonIgnore for sensitive fields\n\n" +
                    "Example:\n" +
                    "```java\n" +
                    "@Data\n" +
                    "public class UserDTO {\n" +
                    "    private Long id;\n" +
                    "    private String username;\n" +
                    "    private String email;\n" +
                    "    // No password, no sensitive fields\n" +
                    "}\n" +
                    "```");
                vuln.setReferences("OWASP API Security Top 10 - API3:2023 Broken Object Property Level Authorization");
                
                vulnerabilities.add(vuln);
            }
            
        } catch (Exception e) {
            log.error("Error testing excessive data exposure: {}", e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> testCORSMisconfiguration(String targetUrl, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .header("User-Agent", config.getUserAgent())
                .header("Origin", "https://evil.com")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, 
                HttpResponse.BodyHandlers.ofString());
            
            String accessControlOrigin = response.headers()
                .firstValue("Access-Control-Allow-Origin")
                .orElse(null);
            
            if ("*".equals(accessControlOrigin)) {
                Vulnerability vuln = new Vulnerability();
                vuln.setTitle("Insecure CORS Configuration");
                vuln.setDescription(
                    "The API allows requests from any origin (Access-Control-Allow-Origin: *). " +
                    "This could allow malicious websites to make requests to your API on behalf of users.");
                vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                vuln.setCvssScore(5.3);
                vuln.setCategory("Security Misconfiguration");
                vuln.setCweId("CWE-346");
                vuln.setAffectedUrl(targetUrl);
                vuln.setEvidence("Access-Control-Allow-Origin: *");
                vuln.setRemediation("CONFIGURE CORS PROPERLY:\n\n" +
                    "For Spring Boot:\n" +
                    "```java\n" +
                    "@Configuration\n" +
                    "public class CorsConfig {\n" +
                    "    @Bean\n" +
                    "    public CorsConfigurationSource corsConfigurationSource() {\n" +
                    "        CorsConfiguration configuration = new CorsConfiguration();\n" +
                    "        configuration.setAllowedOrigins(Arrays.asList(\n" +
                    "            \"https://yourdomain.com\",\n" +
                    "            \"https://app.yourdomain.com\"\n" +
                    "        ));\n" +
                    "        configuration.setAllowedMethods(Arrays.asList(\"GET\", \"POST\", \"PUT\", \"DELETE\"));\n" +
                    "        configuration.setAllowCredentials(true);\n" +
                    "        \n" +
                    "        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();\n" +
                    "        source.registerCorsConfiguration(\"/**\", configuration);\n" +
                    "        return source;\n" +
                    "    }\n" +
                    "}\n" +
                    "```");
                vuln.setReferences("OWASP API Security Top 10 - API8:2023 Security Misconfiguration");
                
                vulnerabilities.add(vuln);
            }
            
        } catch (Exception e) {
            log.error("Error testing CORS: {}", e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> testAPIVersioning(String targetUrl, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Check if API version is in URL
        if (!targetUrl.matches(".*/v\\d+/.*") && !targetUrl.matches(".*/api/\\d+/.*")) {
            Vulnerability vuln = new Vulnerability();
            vuln.setTitle("Missing API Versioning");
            vuln.setDescription(
                "The API endpoint does not include version information in the URL. " +
                "This makes it difficult to maintain backward compatibility and can lead to breaking changes.");
            vuln.setSeverity(Vulnerability.Severity.LOW);
            vuln.setCvssScore(3.0);
            vuln.setCategory("API Design");
            vuln.setAffectedUrl(targetUrl);
            vuln.setEvidence("No version identifier found in URL path");
            vuln.setRemediation("IMPLEMENT API VERSIONING:\n\n" +
                "Best practices:\n" +
                "- URL versioning: /api/v1/users\n" +
                "- Header versioning: Accept: application/vnd.api+json;version=1\n" +
                "- Query parameter: /api/users?version=1\n\n" +
                "Recommended: URL versioning for clarity");
            vuln.setReferences("REST API Best Practices");
            
            vulnerabilities.add(vuln);
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> testAPIDocumentation(String targetUrl, ScanConfig config) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            // Check common documentation endpoints
            String[] docPaths = {
                "/swagger-ui.html",
                "/api-docs",
                "/swagger.json",
                "/openapi.json",
                "/docs",
                "/api/docs"
            };
            
            String baseUrl = targetUrl.substring(0, targetUrl.indexOf("/api/") + 4);
            
            for (String docPath : docPaths) {
                try {
                    HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + docPath))
                        .header("User-Agent", config.getUserAgent())
                        .timeout(Duration.ofSeconds(5))
                        .GET()
                        .build();
                    
                    HttpResponse<String> response = httpClient.send(request, 
                        HttpResponse.BodyHandlers.ofString());
                    
                    if (response.statusCode() == 200) {
                        Vulnerability vuln = new Vulnerability();
                        vuln.setTitle("Publicly Accessible API Documentation");
                        vuln.setDescription(
                            "API documentation is publicly accessible without authentication. " +
                            "This exposes your API structure, endpoints, and parameters to potential attackers.");
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                        vuln.setCvssScore(5.3);
                        vuln.setCategory("Information Disclosure");
                        vuln.setCweId("CWE-200");
                        vuln.setAffectedUrl(baseUrl + docPath);
                        vuln.setEvidence("Documentation accessible at: " + baseUrl + docPath);
                        vuln.setRemediation("SECURE API DOCUMENTATION:\n\n" +
                            "1. Require authentication to access documentation\n" +
                            "2. Disable documentation in production\n" +
                            "3. Use IP whitelisting for internal documentation\n\n" +
                            "For Spring Boot:\n" +
                            "```yaml\n" +
                            "springdoc:\n" +
                            "  swagger-ui:\n" +
                            "    enabled: false  # Disable in production\n" +
                            "```");
                        vuln.setReferences("OWASP API Security Top 10 - API9:2023 Improper Inventory Management");
                        
                        vulnerabilities.add(vuln);
                        break; // Only report once
                    }
                } catch (Exception e) {
                    // Continue checking other paths
                }
            }
            
        } catch (Exception e) {
            log.error("Error testing API documentation: {}", e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    private boolean isAPIEndpoint(String url) {
        String lower = url.toLowerCase();
        return lower.contains("/api/") || 
               lower.matches(".*/v\\d+/.*") ||
               lower.endsWith(".json") ||
               lower.endsWith(".xml");
    }
    
    @Override
    public String getScannerName() {
        return "API Security Scanner";
    }
    
    @Override
    public boolean isApplicable(String targetUrl) {
        return targetUrl.startsWith("http://") || targetUrl.startsWith("https://");
    }
}
