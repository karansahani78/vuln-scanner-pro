package com.security.vulnscanner.service;

import com.security.vulnscanner.model.TechnologyStack;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Component
public class TechnologyDetector {
    
    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build();
    
    public TechnologyStack detectStack(String url) {
        TechnologyStack stack = new TechnologyStack();
        
        try {
            // Fetch page
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("User-Agent", "VulnScanner-Pro/1.0")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            Map<String, java.util.List<String>> headers = response.headers().map();
            String body = response.body();
            
            // Detect components
            stack.setFrontend(detectFrontendFramework(body));
            stack.setBackend(detectBackendFramework(body, headers));
            stack.setDatabase(detectDatabase(body, headers));
            stack.setCdn(detectCDN(headers));
            stack.setWaf(detectWAF(headers, body));
            stack.setJsLibraries(extractJsLibraries(body));
            stack.setCms(detectCMS(body, url));
            
            // Detect security features
            detectSecurityFeatures(stack, headers, body);
            
            log.info("Technology stack detected for {}: Frontend={}, Backend={}", 
                url, stack.getFrontend(), stack.getBackend());
            
        } catch (Exception e) {
            log.error("Error detecting technology stack: {}", e.getMessage());
        }
        
        return stack;
    }
    
    private TechnologyStack.Frontend detectFrontendFramework(String body) {
        if (body.contains("__NEXT_DATA__") || body.contains("_next/static")) {
            return TechnologyStack.Frontend.NEXT_JS;
        }
        if (body.contains("ng-version") || body.contains("ng-app") || body.contains("ng-controller")) {
            return TechnologyStack.Frontend.ANGULAR;
        }
        if (body.contains("__vue") || body.contains("data-v-") || body.contains("vue.js") || body.contains("Vue.js")) {
            return TechnologyStack.Frontend.VUE;
        }
        if (body.contains("data-reactroot") || body.contains("data-reactid") || 
            body.contains("__react") || body.contains("react-root")) {
            return TechnologyStack.Frontend.REACT;
        }
        if (body.contains("__nuxt") || body.contains("__NUXT__")) {
            return TechnologyStack.Frontend.NUXT;
        }
        if (body.contains("__svelte")) {
            return TechnologyStack.Frontend.SVELTE;
        }
        
        // Additional detection via script tags
        if (body.matches("(?s).*<script[^>]*src=['\"][^'\"]*react[^'\"]*['\"].*")) {
            return TechnologyStack.Frontend.REACT;
        }
        if (body.matches("(?s).*<script[^>]*src=['\"][^'\"]*vue[^'\"]*['\"].*")) {
            return TechnologyStack.Frontend.VUE;
        }
        if (body.matches("(?s).*<script[^>]*src=['\"][^'\"]*angular[^'\"]*['\"].*")) {
            return TechnologyStack.Frontend.ANGULAR;
        }
        
        return TechnologyStack.Frontend.UNKNOWN;
    }
    
    private TechnologyStack.Backend detectBackendFramework(String body, Map<String, java.util.List<String>> headers) {
        // Check headers first
        String xPoweredBy = getHeaderValue(headers, "X-Powered-By");
        String server = getHeaderValue(headers, "Server");
        
        if (xPoweredBy != null) {
            if (xPoweredBy.contains("Express")) return TechnologyStack.Backend.EXPRESS;
            if (xPoweredBy.contains("PHP")) return TechnologyStack.Backend.LARAVEL;
            if (xPoweredBy.contains("ASP.NET")) return TechnologyStack.Backend.ASP_NET;
        }
        
        // Server header detection
        if (server != null) {
            if (server.contains("nginx") && body.contains("rails")) {
                return TechnologyStack.Backend.RUBY_ON_RAILS;
            }
            if (server.contains("gunicorn") || server.contains("uvicorn")) {
                return body.contains("django") ? TechnologyStack.Backend.DJANGO : TechnologyStack.Backend.FASTAPI;
            }
        }
        
        // Spring Boot detection
        if (getHeaderValue(headers, "X-Application-Context") != null ||
            body.contains("Whitelabel Error Page") ||
            body.contains("spring-boot") ||
            body.contains("SpringBootApplication")) {
            return TechnologyStack.Backend.SPRING_BOOT;
        }
        
        // Django detection
        if (getHeaderValue(headers, "X-Frame-Options") != null && 
            (body.contains("csrfmiddlewaretoken") || body.contains("django"))) {
            return TechnologyStack.Backend.DJANGO;
        }
        
        // Laravel detection
        if (body.contains("laravel_session") || 
            getHeaderValue(headers, "X-Laravel-Session") != null ||
            body.contains("Laravel")) {
            return TechnologyStack.Backend.LARAVEL;
        }
        
        // Flask detection
        if ((server != null && server.contains("Werkzeug")) ||
            body.contains("flask")) {
            return TechnologyStack.Backend.FLASK;
        }
        
        // FastAPI detection
        if (body.contains("\"detail\":") && body.contains("FastAPI") ||
            server != null && server.contains("uvicorn")) {
            return TechnologyStack.Backend.FASTAPI;
        }
        
        // Ruby on Rails detection
        if (getHeaderValue(headers, "X-Runtime") != null ||
            body.contains("_rails_session") ||
            body.contains("Rails")) {
            return TechnologyStack.Backend.RUBY_ON_RAILS;
        }
        
        // Express.js detection
        if (body.matches("(?s).*powered by Express.*") ||
            getHeaderValue(headers, "X-Powered-By") != null && 
            getHeaderValue(headers, "X-Powered-By").contains("Express")) {
            return TechnologyStack.Backend.EXPRESS;
        }
        
        return TechnologyStack.Backend.UNKNOWN;
    }
    
    private TechnologyStack.Database detectDatabase(String body, Map<String, java.util.List<String>> headers) {
        // Look for database error messages (shouldn't be visible but often are)
        if (body.contains("PostgreSQL") || body.contains("postgres")) {
            return TechnologyStack.Database.POSTGRESQL;
        }
        if (body.contains("MySQL") || body.contains("mysql")) {
            return TechnologyStack.Database.MYSQL;
        }
        if (body.contains("MongoDB") || body.contains("mongo")) {
            return TechnologyStack.Database.MONGODB;
        }
        if (body.contains("Redis") || body.contains("redis")) {
            return TechnologyStack.Database.REDIS;
        }
        if (body.contains("Microsoft SQL Server") || body.contains("MSSQL")) {
            return TechnologyStack.Database.MSSQL;
        }
        if (body.contains("Oracle") || body.contains("ORA-")) {
            return TechnologyStack.Database.ORACLE;
        }
        
        return TechnologyStack.Database.UNKNOWN;
    }
    
    private String detectCDN(Map<String, java.util.List<String>> headers) {
        String server = getHeaderValue(headers, "Server");
        String cfRay = getHeaderValue(headers, "CF-Ray");
        String xAmznTrace = getHeaderValue(headers, "X-Amzn-Trace-Id");
        
        if (cfRay != null) return "Cloudflare";
        if (xAmznTrace != null) return "AWS CloudFront";
        if (server != null && server.contains("cloudflare")) return "Cloudflare";
        if (getHeaderValue(headers, "X-Akamai-Request-ID") != null) return "Akamai";
        if (getHeaderValue(headers, "X-Azure-Ref") != null) return "Azure CDN";
        
        return null;
    }
    
    private String detectWAF(Map<String, java.util.List<String>> headers, String body) {
        // Check for WAF headers
        if (getHeaderValue(headers, "X-Sucuri-ID") != null) return "Sucuri";
        if (getHeaderValue(headers, "X-Cloudflare-Ray") != null) return "Cloudflare WAF";
        if (getHeaderValue(headers, "X-AWS-WAF") != null) return "AWS WAF";
        if (getHeaderValue(headers, "X-Azure-WAF") != null) return "Azure WAF";
        
        // Check body for WAF signatures
        if (body.contains("This request has been blocked by our Web Application Firewall")) {
            return "Generic WAF";
        }
        
        return null;
    }
    
    private java.util.List<TechnologyStack.Library> extractJsLibraries(String body) {
        java.util.List<TechnologyStack.Library> libraries = new java.util.ArrayList<>();
        
        // jQuery
        Pattern jqueryPattern = Pattern.compile("jquery[/-](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE);
        Matcher jqueryMatcher = jqueryPattern.matcher(body);
        if (jqueryMatcher.find()) {
            TechnologyStack.Library lib = new TechnologyStack.Library();
            lib.setName("jQuery");
            lib.setVersion(jqueryMatcher.group(1));
            lib.setConfidence(95);
            libraries.add(lib);
        } else if (body.contains("jquery") || body.contains("jQuery")) {
            TechnologyStack.Library lib = new TechnologyStack.Library();
            lib.setName("jQuery");
            lib.setVersion("unknown");
            lib.setConfidence(70);
            libraries.add(lib);
        }
        
        // Bootstrap
        Pattern bootstrapPattern = Pattern.compile("bootstrap[/-](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE);
        Matcher bootstrapMatcher = bootstrapPattern.matcher(body);
        if (bootstrapMatcher.find()) {
            TechnologyStack.Library lib = new TechnologyStack.Library();
            lib.setName("Bootstrap");
            lib.setVersion(bootstrapMatcher.group(1));
            lib.setConfidence(90);
            libraries.add(lib);
        } else if (body.contains("bootstrap") && body.contains("css")) {
            TechnologyStack.Library lib = new TechnologyStack.Library();
            lib.setName("Bootstrap");
            lib.setVersion("unknown");
            lib.setConfidence(75);
            libraries.add(lib);
        }
        
        // React
        Pattern reactPattern = Pattern.compile("react[.-](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE);
        Matcher reactMatcher = reactPattern.matcher(body);
        if (reactMatcher.find()) {
            TechnologyStack.Library lib = new TechnologyStack.Library();
            lib.setName("React");
            lib.setVersion(reactMatcher.group(1));
            lib.setConfidence(95);
            libraries.add(lib);
        }
        
        // Vue
        Pattern vuePattern = Pattern.compile("vue[.-](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE);
        Matcher vueMatcher = vuePattern.matcher(body);
        if (vueMatcher.find()) {
            TechnologyStack.Library lib = new TechnologyStack.Library();
            lib.setName("Vue.js");
            lib.setVersion(vueMatcher.group(1));
            lib.setConfidence(95);
            libraries.add(lib);
        }
        
        // Angular
        Pattern angularPattern = Pattern.compile("angular[.-](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE);
        Matcher angularMatcher = angularPattern.matcher(body);
        if (angularMatcher.find()) {
            TechnologyStack.Library lib = new TechnologyStack.Library();
            lib.setName("Angular");
            lib.setVersion(angularMatcher.group(1));
            lib.setConfidence(95);
            libraries.add(lib);
        }
        
        // Lodash
        if (body.contains("lodash")) {
            TechnologyStack.Library lib = new TechnologyStack.Library();
            lib.setName("Lodash");
            lib.setVersion("unknown");
            lib.setConfidence(80);
            libraries.add(lib);
        }
        
        // Axios
        if (body.contains("axios")) {
            TechnologyStack.Library lib = new TechnologyStack.Library();
            lib.setName("Axios");
            lib.setVersion("unknown");
            lib.setConfidence(80);
            libraries.add(lib);
        }
        
        // Tailwind CSS
        if (body.contains("tailwind") || body.contains("Tailwind")) {
            TechnologyStack.Library lib = new TechnologyStack.Library();
            lib.setName("Tailwind CSS");
            lib.setVersion("unknown");
            lib.setConfidence(85);
            libraries.add(lib);
        }
        
        return libraries;
    }
    
    private String detectCMS(String body, String url) {
        if (body.contains("wp-content") || body.contains("wordpress")) {
            return "WordPress";
        }
        if (body.contains("Joomla")) {
            return "Joomla";
        }
        if (body.contains("Drupal")) {
            return "Drupal";
        }
        if (body.contains("Shopify")) {
            return "Shopify";
        }
        if (body.contains("Magento")) {
            return "Magento";
        }
        
        return null;
    }
    
    private void detectSecurityFeatures(TechnologyStack stack, 
                                        Map<String, java.util.List<String>> headers, 
                                        String body) {
        TechnologyStack.SecurityFeatures features = stack.getSecurityFeatures();
        
        // CSRF protection
        features.setCsrfProtection(
            body.contains("csrf") || 
            body.contains("_token") ||
            getHeaderValue(headers, "X-CSRF-Token") != null
        );
        
        // Auth method detection
        String authHeader = getHeaderValue(headers, "Authorization");
        if (authHeader != null) {
            if (authHeader.contains("Bearer")) {
                features.setAuthMethod("JWT/Bearer Token");
            } else if (authHeader.contains("Basic")) {
                features.setAuthMethod("Basic Auth");
            }
        } else if (getHeaderValue(headers, "Set-Cookie") != null) {
            features.setAuthMethod("Session Cookie");
        }
        
        // WAF detection
        features.setHasWAF(stack.getWaf() != null);
        
        // Rate limiting (check for rate limit headers)
        features.setHasRateLimiting(
            getHeaderValue(headers, "X-RateLimit-Limit") != null ||
            getHeaderValue(headers, "X-Rate-Limit") != null
        );
    }
    
    private String getHeaderValue(Map<String, java.util.List<String>> headers, String headerName) {
        for (Map.Entry<String, java.util.List<String>> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(headerName)) {
                java.util.List<String> values = entry.getValue();
                return values.isEmpty() ? null : values.get(0);
            }
        }
        return null;
    }
}
