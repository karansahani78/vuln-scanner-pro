package com.security.vulnscanner.service;

import com.security.vulnscanner.model.Vulnerability;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Slf4j
@Component
public class DynamicSeverityCalculator {
    
    public DynamicSeverity calculateDynamicSeverity(Vulnerability vuln, ScanContext context) {
        double baseScore = vuln.getCvssScore() != null ? vuln.getCvssScore() : 5.0;
        Map<String, Double> riskFactors = new HashMap<>();
        
        // 1. Endpoint sensitivity multiplier
        double endpointMultiplier = getEndpointSensitivity(context.getEndpoint());
        riskFactors.put("endpoint_sensitivity", endpointMultiplier);
        
        // 2. Data exposure risk
        double dataMultiplier = getDataExposureRisk(context.getDataType());
        riskFactors.put("data_exposure", dataMultiplier);
        
        // 3. Authentication requirement
        double authMultiplier = getAuthenticationRisk(context);
        riskFactors.put("authentication", authMultiplier);
        
        // 4. Exploitability
        double exploitMultiplier = getExploitabilityScore(vuln);
        riskFactors.put("exploitability", exploitMultiplier);
        
        // 5. User exposure
        double userMultiplier = getUserExposure(context);
        riskFactors.put("user_exposure", userMultiplier);
        
        // 6. Compliance impact
        double complianceMultiplier = getComplianceImpact(context.getApplicableFrameworks());
        riskFactors.put("compliance", complianceMultiplier);
        
        // Calculate final score
        double contextMultiplier = endpointMultiplier * dataMultiplier * authMultiplier * 
                                   exploitMultiplier * userMultiplier * complianceMultiplier;
        
        double finalScore = baseScore * Math.pow(contextMultiplier, 0.4); // Dampened multiplier
        finalScore = Math.min(10.0, finalScore); // Cap at 10
        
        String severity = mapToSeverity(finalScore);
        String businessRisk = generateBusinessRisk(finalScore, context);
        String priority = generatePriority(finalScore, context);
        
        log.debug("Dynamic severity calculated: Base={}, Context={}, Final={}, Severity={}", 
            baseScore, contextMultiplier, finalScore, severity);
        
        return new DynamicSeverity(baseScore, finalScore, severity, businessRisk, priority, riskFactors);
    }
    
    private double getEndpointSensitivity(String endpoint) {
        if (endpoint == null) return 1.0;
        
        String lower = endpoint.toLowerCase();
        
        // Payment/financial endpoints
        if (lower.matches(".*(payment|checkout|billing|invoice|transaction|purchase).*")) {
            return 1.8;
        }
        
        // Authentication/authorization
        if (lower.matches(".*(auth|login|oauth|token|session|password|credential).*")) {
            return 1.7;
        }
        
        // Admin endpoints
        if (lower.matches(".*(admin|dashboard|internal|manage|control).*")) {
            return 1.7;
        }
        
        // User data endpoints
        if (lower.matches(".*(user|profile|account|settings|personal).*")) {
            return 1.5;
        }
        
        // API endpoints
        if (lower.contains("/api/")) {
            return 1.3;
        }
        
        // Public content
        if (lower.matches(".*(about|contact|blog|public|home|landing).*")) {
            return 0.7;
        }
        
        return 1.0;
    }
    
    private double getDataExposureRisk(DataType dataType) {
        if (dataType == null) return 1.0;
        
        return switch (dataType) {
            case PAYMENT_INFO -> 2.0;        // Credit cards, bank accounts
            case HEALTH_DATA -> 2.0;         // HIPAA protected
            case CREDENTIALS -> 1.9;         // Passwords, API keys, tokens
            case PII -> 1.8;                 // Names, emails, addresses, SSN
            case BUSINESS_CRITICAL -> 1.7;   // Trade secrets, financial data
            case INTERNAL_DATA -> 1.4;       // Internal documents, reports
            case USER_CONTENT -> 1.2;        // User-generated content
            case PUBLIC -> 0.6;              // Already public information
            case UNKNOWN -> 1.0;
        };
    }
    
    private double getAuthenticationRisk(ScanContext context) {
        if (!context.isRequiresAuthentication()) {
            return 1.5; // Publicly exploitable = higher risk
        }
        if (context.isRequiresAdminPrivileges()) {
            return 0.8; // Requires admin = lower likelihood
        }
        return 1.0; // Requires regular authentication
    }
    
    private double getExploitabilityScore(Vulnerability vuln) {
        // Check if there's a public exploit
        if (vuln.getCveId() != null && !vuln.getCveId().isEmpty()) {
            return 1.6; // CVE usually means public exploit exists
        }
        
        // Check vulnerability type exploitability
        String category = vuln.getCategory() != null ? vuln.getCategory().toLowerCase() : "";
        
        if (category.contains("sql injection") || category.contains("command injection")) {
            return 1.7; // Highly exploitable
        }
        if (category.contains("authentication") || category.contains("authorization")) {
            return 1.6; // Critical but may need more steps
        }
        if (category.contains("xss") || category.contains("cross-site")) {
            return 1.3; // Requires user interaction
        }
        if (category.contains("csrf")) {
            return 1.2; // Requires social engineering
        }
        if (category.contains("information disclosure")) {
            return 1.1; // Easy but lower impact
        }
        
        return 1.0;
    }
    
    private double getUserExposure(ScanContext context) {
        if (context.getUserBase() == null) return 1.0;
        
        return switch (context.getUserBase()) {
            case ALL_USERS -> 1.5;          // Affects everyone
            case AUTHENTICATED_USERS -> 1.3; // Affects logged-in users
            case ADMIN_USERS -> 1.1;         // Affects admins only
            case SPECIFIC_FEATURE -> 0.9;    // Affects users of specific feature
            case LIMITED -> 0.7;             // Very limited exposure
        };
    }
    
    private double getComplianceImpact(Set<ComplianceFramework> frameworks) {
        if (frameworks == null || frameworks.isEmpty()) return 1.0;
        
        double impact = 1.0;
        if (frameworks.contains(ComplianceFramework.PCI_DSS)) impact *= 1.5;
        if (frameworks.contains(ComplianceFramework.HIPAA)) impact *= 1.6;
        if (frameworks.contains(ComplianceFramework.GDPR)) impact *= 1.4;
        if (frameworks.contains(ComplianceFramework.SOC2)) impact *= 1.3;
        if (frameworks.contains(ComplianceFramework.ISO_27001)) impact *= 1.3;
        
        return Math.min(impact, 2.0); // Cap multiplier
    }
    
    private String mapToSeverity(double score) {
        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 4.0) return "MEDIUM";
        if (score >= 0.1) return "LOW";
        return "INFO";
    }
    
    private String generateBusinessRisk(double score, ScanContext context) {
        if (score >= 9.0) {
            return "Immediate risk of data breach, financial loss, or regulatory fines";
        }
        if (score >= 7.0) {
            return "High risk of security incident, potential data exposure";
        }
        if (score >= 4.0) {
            return "Moderate risk, should be addressed in current sprint";
        }
        return "Low risk, address in regular maintenance cycle";
    }
    
    private String generatePriority(double score, ScanContext context) {
        if (score >= 9.0) return "P0"; // Fix immediately (today)
        if (score >= 7.0) return "P1"; // Fix this week
        if (score >= 4.0) return "P2"; // Fix this sprint
        return "P3"; // Fix when convenient
    }
    
    @Data
    @AllArgsConstructor
    public static class DynamicSeverity {
        private double baseScore;
        private double contextScore;
        private String severityLevel;
        private String businessRisk;
        private String priority;
        private Map<String, Double> riskFactors;
    }
    
    @Data
    public static class ScanContext {
        private String endpoint;
        private DataType dataType = DataType.UNKNOWN;
        private boolean requiresAuthentication;
        private boolean requiresAdminPrivileges;
        private UserBase userBase = UserBase.ALL_USERS;
        private Set<ComplianceFramework> applicableFrameworks = new HashSet<>();
    }
    
    public enum DataType {
        PAYMENT_INFO,
        HEALTH_DATA,
        CREDENTIALS,
        PII,
        BUSINESS_CRITICAL,
        INTERNAL_DATA,
        USER_CONTENT,
        PUBLIC,
        UNKNOWN
    }
    
    public enum UserBase {
        ALL_USERS,
        AUTHENTICATED_USERS,
        ADMIN_USERS,
        SPECIFIC_FEATURE,
        LIMITED
    }
    
    public enum ComplianceFramework {
        PCI_DSS,
        HIPAA,
        GDPR,
        SOC2,
        ISO_27001,
        CCPA,
        NIST
    }
}
